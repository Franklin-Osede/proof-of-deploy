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
// It exists alongside the v1 publisher rather than replacing it. Wiring this to
// the v1 contract would require weakening what "confirmed" means, because the
// v1 record has no incarnation and so could never be matched exactly. A
// deliberately vague confirmation is the exact ambiguity this design removes,
// so the switch happens with the protocol switch and not before.
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
//   - Mined-success confirms. So does a matching on-chain record, which is how
//     a lost receipt is recovered.
//   - A newer revision invalidates the older one, and no in-flight worker may
//     confirm or publish on behalf of a revision that is no longer desired.
//   - The chain is queried before the first Prepare, always. That is also what
//     recovers state after a restart, when every attempt in memory is gone.
type PublisherV2 struct {
	queue  workqueue.RateLimitingInterface
	signer Signer
	chain  ChainV2
	log    logr.Logger

	// fingerprint is fixed for the process: it identifies this signer's key,
	// and knowing it without signing is what lets the pre-send reconciliation
	// match a complete revision before any KMS call is made.
	fingerprint [32]byte

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
type OnChain struct {
	Exists bool
	Key    RevisionKey
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

// Signer is declared in publisher.go and shared: both publishers need exactly
// the same slice of the KMS signer.

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
}

// NewV2 builds a publisher. The signer's public key is read once so the
// fingerprint is available without signing.
func NewV2(signer Signer, chain ChainV2, log logr.Logger) *PublisherV2 {
	return &PublisherV2{
		queue: workqueue.NewRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, 5*time.Minute),
		),
		signer:      signer,
		chain:       chain,
		log:         log.WithName("publisher-v2"),
		fingerprint: attest.PublicKeyFingerprintBytes(signer.PublicKeyDER()),
		state:       make(map[[32]byte]*workloadState),
	}
}

// Enqueue records a desired revision. It never blocks and never signs, so the
// reconcile loop pays nothing for it.
//
// A revision identical to what we have already confirmed is dropped. Anything
// else supersedes whatever was desired before for that workload, including any
// attempt in flight for it.
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
	if st.confirmed != nil && *st.confirmed == key {
		p.mu.Unlock()
		return nil
	}
	if st.seq != 0 && st.key == key {
		// Already the desired revision; the existing attempt continues.
		p.mu.Unlock()
		p.queue.Add(workloadID)
		return nil
	}

	p.seq++
	st.desired = d
	st.seq = p.seq
	st.key = key
	// A new revision invalidates the old signature and the old transaction.
	// Keeping either would risk publishing a superseded state.
	st.signature = nil
	st.prepared = nil
	p.mu.Unlock()

	p.queue.Add(workloadID)
	return nil
}

func (p *PublisherV2) revisionKey(d Desired) RevisionKey {
	env := attest.EnvelopeV2{Version: d.Version, Identity: d.Identity, UID: d.UID, ConfigHash: d.ConfigHash}
	return RevisionKey{
		Version:     uint16(d.Version),
		ConfigHash:  d.ConfigHash,
		Incarnation: env.Incarnation(),
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

// process advances one workload by one step. It returns (true, nil) when the
// desired revision was confirmed but a newer one is already waiting.
func (p *PublisherV2) process(ctx context.Context, id [32]byte) (bool, error) {
	rev, ok := p.snapshot(id)
	if !ok {
		return false, nil
	}

	// Always ask the chain first. This is what makes a restart safe: every
	// attempt in memory is gone, but the record is not, so a workload already
	// published is never published again.
	onchain, err := p.chain.Latest(ctx, id)
	if err != nil {
		return false, fmt.Errorf("reading current attestation: %w", err)
	}
	if onchain.Exists && onchain.Key == rev.key {
		return p.confirm(id, rev), nil
	}

	prepared, err := p.prepareOnce(ctx, id, rev)
	if err != nil {
		return false, err
	}

	sent, err := p.chain.Send(ctx, prepared)
	if err != nil {
		// Nothing was sent; this is a fault, not uncertainty.
		return false, fmt.Errorf("sending publish: %w", err)
	}
	if sent == SendUnknown {
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
		return p.confirm(id, rev), nil

	case WaitReverted:
		// Definitive: it did not take effect, so the attempt is spent and a
		// fresh one may be prepared. Backoff is kept deliberately -- a
		// deterministic revert would otherwise spin.
		p.discardAttempt(id, rev.seq)
		return false, fmt.Errorf("publish reverted for %s (tx %s)", rev.desired.Label, prepared.Hash())

	default:
		// Unknown. Keep the attempt: it may still mine, and only the chain can
		// settle it. Reconcile immediately so a lost receipt does not cost a
		// whole backoff cycle.
		latest, lerr := p.chain.Latest(ctx, id)
		if lerr == nil && latest.Exists && latest.Key == rev.key {
			p.log.Info("attestation recovered by reconciliation; receipt was lost",
				"deployment", rev.desired.Label, "tx", prepared.Hash())
			return p.confirm(id, rev), nil
		}
		return false, fmt.Errorf("publish outcome unknown for %s (tx %s)", rev.desired.Label, prepared.Hash())
	}
}

// snapshot copies the desired revision under lock.
func (p *PublisherV2) snapshot(id [32]byte) (workloadState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.state[id]
	if !ok || st.seq == 0 {
		return workloadState{}, false
	}
	if st.confirmed != nil && *st.confirmed == st.key {
		return workloadState{}, false
	}
	return *st, true
}

// prepareOnce signs and prepares a revision the first time, and reuses both
// afterwards. Preparing again would allocate a new nonce and publish twice.
func (p *PublisherV2) prepareOnce(ctx context.Context, id [32]byte, rev workloadState) (PreparedTx, error) {
	if rev.prepared != nil {
		return rev.prepared, nil
	}

	sig := rev.signature
	if sig == nil {
		env := attest.EnvelopeV2{
			Version:    rev.desired.Version,
			Identity:   rev.desired.Identity,
			UID:        rev.desired.UID,
			ConfigHash: rev.desired.ConfigHash,
		}
		digest, err := env.SigningDigest()
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
	// If the revision moved on, the caller's result will be discarded anyway.
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
	st.prepared = nil
	return false
}

func (p *PublisherV2) discardAttempt(id [32]byte, seq uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.state[id]; ok && st.seq == seq {
		st.prepared = nil
	}
}
