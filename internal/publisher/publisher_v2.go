/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package publisher

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
)

// PublisherV2 owns the lifecycle of an attestation from "we observed this" to
// "the chain holds it".
//
// The state it keeps per workload:
//
//	desired    the revision we want on chain, with its signature
//	confirmed  the revision we have observed on chain
//	attempt    the single prepared transaction for the desired revision
//
// The rules that matter, each of which has a test:
//
//   - A revision is signed once and prepared once. Retries reuse both.
//   - Unknown keeps the attempt. Preparing a replacement would take a fresh
//     nonce and publish twice.
//   - Reverted discards the attempt; it definitively did not take effect.
//   - Mined-success confirms, unless another of our transactions landed while
//     it was unresolved; then only a chain read does. A matching on-chain
//     record also confirms, which is how a lost receipt is recovered.
//   - A newer revision invalidates the older one, and no in-flight worker may
//     confirm or publish on behalf of a revision that is no longer desired.
//   - A confirmation is only trusted until a different revision is desired.
//     After that something may have been sent for it, so a rollback to the
//     confirmed state is re-checked against the chain, never assumed.
//   - Superseded work is abandoned before it is sent, not after. A sent
//     transaction cannot be recalled.
//   - The chain is queried before the first Prepare, always. That is also what
//     recovers state after a restart, when every attempt in memory is gone.
//
// Assumption: Latest sees a write whose receipt has already been returned.
// That holds on a single node. A load-balanced RPC endpoint can serve a stale
// read, and a rollback decided on it can stay uncorrected until the next event
// for that workload.
type PublisherV2 struct {
	queue  workqueue.RateLimitingInterface
	signer Signer
	chain  ChainV2
	log    logr.Logger

	// fingerprint is fixed for the process: it identifies this signer's key,
	// and knowing it without signing is what lets the pre-send reconciliation
	// match a complete revision before any KMS call is made.
	fingerprint [32]byte
	// pub is the same key, parsed once, so reconciliation can VERIFY an
	// on-chain signature rather than merely compare a fingerprint to it.
	pub *ecdsa.PublicKey

	mu    sync.Mutex
	state map[[32]byte]*workloadState
	seq   uint64
}

// Desired is what the reconciler asks for: an identity and the state observed
// for it. The signature is not here because signing costs a KMS call, and the
// reconcile loop must never pay for one.
type Desired struct {
	Identity   attest.WorkloadIdentityV2
	Version    attest.Version
	ConfigHash [32]byte
	// UID is the observed object's Kubernetes UID. Empty means no incarnation
	// is bound, which the verifier treats as weaker.
	UID string
	// Label is for logs only. It is never hashed, signed or published.
	Label string
}

// RevisionKey identifies a revision completely enough to say whether an
// on-chain record IS it.
//
// All four fields are required. Matching on the config hash alone would accept
// a record published for a different incarnation, under a different protocol
// version, or by a different signer.
type RevisionKey struct {
	Version     uint16
	ConfigHash  [32]byte
	Incarnation [32]byte
	Fingerprint [32]byte
}

// OnChain is the registry's view of a workload.
//
// Signature is carried because the key fields alone cannot establish that a
// record is ours. The fingerprint in a record is a value the WRITER chose: an
// account able to write can put our fingerprint next to a meaningless
// signature. Confirming on field equality would then leave the workload
// looking attested while no valid attestation exists, and the operator would
// stop trying to publish one.
type OnChain struct {
	Exists    bool
	Key       RevisionKey
	Signature []byte
}

// PreparedTx is an opaque handle to a signed, unsent transaction. The publisher
// never inspects it; it only needs to hold the same one across retries.
type PreparedTx interface {
	Hash() string
}

// SendOutcome and WaitOutcome mirror the chain package's vocabulary without
// importing it, so this state machine can be tested with fakes.
type SendOutcome int

const (
	SendUnknown SendOutcome = iota
	SendAccepted
)

type WaitOutcome int

const (
	WaitUnknown WaitOutcome = iota
	WaitMinedSuccess
	WaitReverted
)

// ChainV2 is the narrow slice of the chain client this needs.
type ChainV2 interface {
	Latest(ctx context.Context, workloadID [32]byte) (OnChain, error)
	Prepare(ctx context.Context, workloadID [32]byte, key RevisionKey, signature []byte) (PreparedTx, error)
	// Send never reports a transport failure as an error: that is not evidence
	// the node lacks the transaction. Errors are for faults where nothing was
	// sent at all.
	Send(ctx context.Context, p PreparedTx) (SendOutcome, error)
	Wait(ctx context.Context, p PreparedTx) (WaitOutcome, error)
}

type workloadState struct {
	desired Desired
	// seq increases with every newly desired revision. An attempt carries the
	// seq it was made for, which is how a superseded worker recognises that its
	// result no longer applies.
	seq       uint64
	key       RevisionKey
	signature []byte
	prepared  PreparedTx
	confirmed *RevisionKey
	// sent holds every transaction handed to Send whose own outcome has not
	// been observed, for this revision or a superseded one. An entry leaves
	// only when its Wait reports mined or reverted. While any remain, a
	// confirmation is only what the last read showed, so the chain keeps
	// being read. prepared, when sent, is one of these entries.
	sent []sentTx
}

// sentTx is a transaction that may be on its way to the chain.
type sentTx struct {
	tx  PreparedTx
	key RevisionKey
	// overlapped is set when another of our transactions was observed to land
	// while this one was unresolved. Its own receipt then cannot say which of
	// the two the chain holds.
	overlapped bool
}

// sentIndex returns the position of tx in sent, or -1.
func (st *workloadState) sentIndex(tx PreparedTx) int {
	for i, s := range st.sent {
		if s.tx.Hash() == tx.Hash() {
			return i
		}
	}
	return -1
}

// NewV2 builds a publisher. The signer's public key is read and parsed once:
// the fingerprint lets reconciliation match a revision without signing, and the
// parsed key lets it verify what it matched.
//
// A signer whose public key cannot be parsed is a configuration fault, so it
// fails here rather than at the first publication.
func NewV2(signer Signer, chain ChainV2, log logr.Logger) (*PublisherV2, error) {
	der := signer.PublicKeyDER()
	pub, err := attest.ParsePublicKeyDER(der)
	if err != nil {
		return nil, fmt.Errorf("publisher: signer public key: %w", err)
	}
	return &PublisherV2{
		queue: workqueue.NewRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, 5*time.Minute),
		),
		signer:      signer,
		chain:       chain,
		log:         log.WithName("publisher-v2"),
		fingerprint: attest.PublicKeyFingerprintBytes(der),
		pub:         pub,
		state:       make(map[[32]byte]*workloadState),
	}, nil
}

// envelopeFor rebuilds the signed envelope for a revision. It is the same
// construction the signing path uses, which is what makes verification
// meaningful rather than a second, subtly different opinion.
func (p *PublisherV2) envelopeFor(d Desired) attest.EnvelopeV2 {
	return attest.EnvelopeV2{
		Version:    d.Version,
		Identity:   d.Identity,
		UID:        d.UID,
		ConfigHash: d.ConfigHash,
	}
}

// recordIsOurs reports whether an on-chain record really is this revision,
// signed by this signer.
//
// Field equality is not enough. A record carries the fingerprint its writer
// chose, so matching fields prove only that somebody claimed our key. The
// signature is what proves it: it is verified against the envelope rebuilt from
// what we want, so any difference in identity, incarnation, version or config
// makes the digest differ and verification fail.
func (p *PublisherV2) recordIsOurs(d Desired, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	digest, err := p.envelopeFor(d).SigningDigest()
	if err != nil {
		return false
	}
	return attest.VerifyConfigHashSignature(p.pub, digest, sig)
}

// Enqueue records a desired revision. It never blocks and never signs, so the
// reconcile loop pays nothing for it.
//
// A revision that is both desired and confirmed is dropped, unless a sent
// transaction is unresolved and may still change what the chain holds. Anything else
// supersedes whatever was desired before for that workload, including any
// attempt in flight for it.
//
// Being confirmed alone is not enough to drop it. If A is confirmed and B is
// desired, B may already have been sent; a return to A must become the desired
// revision again, and the chain decides whether it still needs publishing.
func (p *PublisherV2) Enqueue(d Desired) error {
	workloadID, err := d.Identity.WorkloadID()
	if err != nil {
		return fmt.Errorf("publisher: %w", err)
	}
	key := p.revisionKey(d)

	p.mu.Lock()
	st, ok := p.state[workloadID]
	if !ok {
		st = &workloadState{}
		p.state[workloadID] = st
	}
	if st.seq != 0 && st.key == key {
		confirmed := st.confirmed != nil && *st.confirmed == key && len(st.sent) == 0
		p.mu.Unlock()
		if !confirmed {
			// Already the desired revision; the existing attempt continues.
			p.queue.Add(workloadID)
		}
		return nil
	}

	p.seq++
	st.desired = d
	st.seq = p.seq
	st.key = key
	// A new revision invalidates the old signature and the old transaction.
	// Keeping either would risk publishing a superseded state.
	// A transaction already sent stays in sent, where it keeps being checked.
	st.signature = nil
	st.prepared = nil
	for _, s := range st.sent {
		if s.key == key {
			// An earlier attempt for this same revision is still unresolved.
			// It becomes the attempt again: preparing another would publish
			// twice.
			st.prepared = s.tx
		}
	}
	// What was confirmed described the chain before the revision now being
	// replaced could be sent. It is no longer evidence of what the chain holds.
	st.confirmed = nil
	p.mu.Unlock()

	p.queue.Add(workloadID)
	return nil
}

func (p *PublisherV2) revisionKey(d Desired) RevisionKey {
	return RevisionKey{
		Version:     uint16(d.Version),
		ConfigHash:  d.ConfigHash,
		Incarnation: p.envelopeFor(d).Incarnation(),
		Fingerprint: p.fingerprint,
	}
}

// NeedLeaderElection ensures only the elected leader publishes.
func (p *PublisherV2) NeedLeaderElection() bool { return true }

// Start runs the worker until ctx is cancelled.
func (p *PublisherV2) Start(ctx context.Context) error {
	p.log.Info("attestation publisher started")
	go func() {
		<-ctx.Done()
		p.queue.ShutDown()
	}()
	for p.processNext(ctx) {
	}
	p.log.Info("attestation publisher stopped")
	return nil
}

func (p *PublisherV2) processNext(ctx context.Context) bool {
	item, shutdown := p.queue.Get()
	if shutdown {
		return false
	}
	defer p.queue.Done(item)

	id := item.([32]byte)
	again, err := p.process(ctx, id)
	switch {
	case err != nil:
		p.log.Error(err, "publish attempt failed; will retry with backoff",
			"requeues", p.queue.NumRequeues(item))
		p.queue.AddRateLimited(item)
	case again:
		// Confirmed, but something newer is already desired.
		p.queue.Forget(item)
		p.queue.Add(item)
	default:
		p.queue.Forget(item)
	}
	return true
}

// process advances one workload by one step. It returns (true, nil) when a
// newer revision is already waiting: either this one was confirmed after being
// superseded, or it was superseded before it could be sent.
func (p *PublisherV2) process(ctx context.Context, id [32]byte) (bool, error) {
	rev, ok := p.snapshot(id)
	if !ok {
		return false, nil
	}

	// Re-check every unresolved transaction other than the current attempt,
	// which is checked below. This comes before the chain read, so the read
	// reflects whatever these are now known to have done.
	for _, s := range rev.sent {
		if rev.prepared == nil || s.tx.Hash() != rev.prepared.Hash() {
			p.recheck(ctx, id, s.tx)
		}
	}

	// Always ask the chain first. This is what makes a restart safe: every
	// attempt in memory is gone, but the record is not, so a workload already
	// published is never published again.
	onchain, err := p.chain.Latest(ctx, id)
	if err != nil {
		return false, fmt.Errorf("reading current attestation: %w", err)
	}
	if onchain.Exists && onchain.Key == rev.key {
		if p.recordIsOurs(rev.desired, onchain.Signature) {
			if rev.prepared != nil && rev.sentIndex(rev.prepared) >= 0 {
				p.recheck(ctx, id, rev.prepared)
			}
			return p.finish(id, p.confirm(id, rev))
		}
		// Every field matches and the signature does not verify. Something
		// wrote our fingerprint over a signature we did not make. Publishing a
		// correct record is the only response available here; the operator
		// cannot remove the bad one.
		p.log.Info("on-chain record matches this revision but its signature does not verify; republishing",
			"deployment", rev.desired.Label)
	}

	prepared, err := p.prepareOnce(ctx, id, rev)
	if err != nil {
		return false, err
	}

	// Signing and the chain read both take time, and a newer revision may have
	// arrived during either. This is the last point at which that can be acted
	// on: once sent, the transaction cannot be recalled. The check and the send
	// are not atomic, so a revision arriving between them is still sent. It
	// is recorded as sent first, so its outcome keeps being checked.
	current, fresh := p.markSent(id, rev.seq, prepared, rev.key)
	if !current {
		p.log.V(1).Info("revision superseded before sending; abandoning it",
			"deployment", rev.desired.Label)
		return true, nil
	}

	sent, err := p.chain.Send(ctx, prepared)
	switch {
	case err != nil && fresh:
		// Nothing was sent; this is a fault, not uncertainty.
		p.unmarkSent(id, prepared)
		return false, fmt.Errorf("sending publish: %w", err)
	case err != nil:
		// It was sent on an earlier pass, so the error means nothing was sent
		// THIS time, not that nothing ever was. The node may no longer hold it
		// because it already mined. Its receipt is what settles it, so wait.
		p.log.Info("resending an already sent transaction failed; reading its receipt",
			"deployment", rev.desired.Label, "tx", prepared.Hash(), "error", err.Error())
	case sent == SendUnknown:
		// "Already known" reports unknown too, so the transaction may well be
		// at the node. Waiting is correct; assuming nothing happened is what
		// causes a second nonce and a second publication.
		p.log.V(1).Info("send outcome unknown; waiting rather than resending",
			"deployment", rev.desired.Label, "tx", prepared.Hash())
	}

	outcome, err := p.chain.Wait(ctx, prepared)
	if err != nil {
		return false, fmt.Errorf("waiting for publish: %w", err)
	}

	switch outcome {
	case WaitMinedSuccess:
		p.log.Info("attestation published",
			"deployment", rev.desired.Label,
			"hashVersion", rev.desired.Version.String(),
			"tx", prepared.Hash())
		if !p.resolve(id, prepared, outcome) {
			return p.finish(id, p.confirm(id, rev))
		}
		// Another of our transactions landed while this one was unresolved, so
		// this receipt does not say which of them the chain holds. Only a read
		// does.

	case WaitReverted:
		// Definitive: it did not take effect, so the attempt is spent and a
		// fresh one may be prepared. Backoff is kept deliberately -- a
		// deterministic revert would otherwise spin.
		p.resolve(id, prepared, outcome)
		return false, fmt.Errorf("publish reverted for %s (tx %s)", rev.desired.Label, prepared.Hash())
	}

	// Unknown: keep the attempt, it may still mine, and only the chain can
	// settle it. Reconcile immediately so a lost receipt does not cost a whole
	// backoff cycle.
	latest, lerr := p.chain.Latest(ctx, id)
	if lerr == nil && latest.Exists && latest.Key == rev.key &&
		p.recordIsOurs(rev.desired, latest.Signature) {
		p.log.Info("attestation recovered by reconciliation; receipt was lost",
			"deployment", rev.desired.Label, "tx", prepared.Hash())
		return p.finish(id, p.confirm(id, rev))
	}
	if outcome == WaitMinedSuccess {
		return false, fmt.Errorf("publish for %s mined (tx %s) but the chain holds another record; re-reading",
			rev.desired.Label, prepared.Hash())
	}
	return false, fmt.Errorf("publish outcome unknown for %s (tx %s)", rev.desired.Label, prepared.Hash())
}

// finish ends a pass that confirmed. Work stops only when nothing sent is
// unresolved; until then the error sends the workload back through the
// rate-limited queue, so it is re-checked without another Enqueue.
func (p *PublisherV2) finish(id [32]byte, again bool) (bool, error) {
	if again {
		return true, nil
	}
	p.mu.Lock()
	n := 0
	if st, ok := p.state[id]; ok {
		n = len(st.sent)
	}
	p.mu.Unlock()
	if n > 0 {
		return false, fmt.Errorf("confirmed, but %d sent transaction(s) are unresolved; re-checking", n)
	}
	return false, nil
}

// snapshot copies the desired revision under lock.
func (p *PublisherV2) snapshot(id [32]byte) (workloadState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if !ok || st.seq == 0 {
		return workloadState{}, false
	}
	if st.confirmed != nil && *st.confirmed == st.key && len(st.sent) == 0 {
		return workloadState{}, false
	}
	rev := *st
	rev.sent = append([]sentTx(nil), st.sent...)
	return rev, true
}

// prepareOnce signs and prepares a revision the first time, and reuses both
// afterwards. Preparing again would allocate a new nonce and publish twice.
func (p *PublisherV2) prepareOnce(ctx context.Context, id [32]byte, rev workloadState) (PreparedTx, error) {
	if rev.prepared != nil {
		return rev.prepared, nil
	}

	sig := rev.signature
	if sig == nil {
		digest, err := p.envelopeFor(rev.desired).SigningDigest()
		if err != nil {
			return nil, fmt.Errorf("building signing digest: %w", err)
		}
		sig, err = p.signer.SignDigest(ctx, digest)
		if err != nil {
			return nil, fmt.Errorf("signing: %w", err)
		}
	}

	prepared, err := p.chain.Prepare(ctx, id, rev.key, sig)
	if err != nil {
		return nil, fmt.Errorf("preparing publish: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if ok && st.seq == rev.seq {
		st.signature = sig
		st.prepared = prepared
	}
	// If the revision moved on, nothing is cached; process sees the same thing
	// before sending and abandons the attempt.
	return prepared, nil
}

// confirm records that the chain holds this revision. It refuses to confirm on
// behalf of a revision that is no longer desired. Reports whether something
// newer is waiting.
func (p *PublisherV2) confirm(id [32]byte, rev workloadState) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if !ok {
		return false
	}
	key := rev.key
	st.confirmed = &key
	if st.seq != rev.seq {
		// Superseded while in flight. What we confirmed is true of the chain,
		// but it is not what is wanted now.
		return true
	}
	// A sent attempt whose outcome is unknown is kept: it may still mine.
	if st.prepared != nil && st.sentIndex(st.prepared) < 0 {
		st.prepared = nil
	}
	return false
}

// markSent records tx as sent, if seq is still the desired revision. It
// reports whether it is, and whether this call added the entry.
func (p *PublisherV2) markSent(id [32]byte, seq uint64, tx PreparedTx, key RevisionKey) (current, fresh bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if !ok || st.seq != seq {
		return false, false
	}
	if st.sentIndex(tx) >= 0 {
		return true, false
	}
	st.sent = append(st.sent, sentTx{tx: tx, key: key})
	return true, true
}

// unmarkSent forgets tx after a Send that reported nothing was sent.
func (p *PublisherV2) unmarkSent(id [32]byte, tx PreparedTx) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.state[id]; ok {
		if i := st.sentIndex(tx); i >= 0 {
			st.sent = append(st.sent[:i:i], st.sent[i+1:]...)
		}
	}
}

// recheck asks for a sent transaction's outcome again and records it.
func (p *PublisherV2) recheck(ctx context.Context, id [32]byte, tx PreparedTx) {
	outcome, err := p.chain.Wait(ctx, tx)
	if err != nil {
		p.log.V(1).Info("re-checking a sent transaction failed; it stays tracked", "tx", tx.Hash(), "error", err.Error())
		return
	}
	p.resolve(id, tx, outcome)
}

// resolve records what a sent transaction's own Wait reported. Only mined and
// reverted end tracking. A mined transaction changed the chain, so what was
// confirmed is no longer evidence, and every transaction still unresolved is
// marked overlapped. It reports whether tx itself was overlapped.
func (p *PublisherV2) resolve(id [32]byte, tx PreparedTx, outcome WaitOutcome) bool {
	if outcome != WaitMinedSuccess && outcome != WaitReverted {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if !ok {
		return false
	}
	overlapped := false
	if i := st.sentIndex(tx); i >= 0 {
		overlapped = st.sent[i].overlapped
		st.sent = append(st.sent[:i:i], st.sent[i+1:]...)
	}
	if st.prepared != nil && st.prepared.Hash() == tx.Hash() {
		st.prepared = nil
	}
	if outcome == WaitMinedSuccess {
		st.confirmed = nil
		for i := range st.sent {
			st.sent[i].overlapped = true
		}
	}
	return overlapped
}
