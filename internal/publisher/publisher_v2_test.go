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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
)

// --- fakes ------------------------------------------------------------------

// fakeSigner signs for real. A stub returning arbitrary bytes would make the
// reconciliation tests meaningless, since the whole point is that a record is
// accepted only when its signature verifies.
type fakeSigner struct {
	key   *ecdsa.PrivateKey
	der   []byte
	calls int
	err   error
	// onSign runs before signing, which is how a revision arriving while KMS
	// is being called is expressed.
	onSign func()
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &fakeSigner{key: k, der: der}
}

func (f *fakeSigner) PublicKeyDER() []byte { return f.der }
func (f *fakeSigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	f.calls++
	if f.onSign != nil {
		f.onSign()
	}
	if f.err != nil {
		return nil, f.err
	}
	return ecdsa.SignASN1(rand.Reader, f.key, d[:])
}

// sign produces the signature this signer would have made for a revision,
// without going through the publisher. Used to plant on-chain records.
func (f *fakeSigner) sign(t *testing.T, p *PublisherV2, d Desired) []byte {
	t.Helper()
	digest, err := p.envelopeFor(d).SigningDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

type fakeTx struct{ hash string }

func (f fakeTx) Hash() string { return f.hash }

// fakeChain is scripted per test. Each hook may mutate the record, which is how
// "the transaction mined late" and "the receipt was lost" are expressed.
type fakeChain struct {
	mu sync.Mutex

	record    *RevisionKey // nil means absent
	recordSig []byte
	prepares  int
	sends     int
	waits     int
	prepared  []PreparedTx

	latestErr error
	onPrepare func(key RevisionKey) (SendOutcome, WaitOutcome)
	sendOut   SendOutcome
	waitOut   WaitOutcome
	onWait    func(c *fakeChain, p PreparedTx)
	sendErr   error

	// waitFor, when set, decides the outcome of each Wait instead of waitOut.
	waitFor func(PreparedTx) WaitOutcome
	// sendErrFor, when set, decides each Send's error instead of sendErr.
	sendErrFor func(PreparedTx) error
}

func (c *fakeChain) Latest(_ context.Context, _ [32]byte) (OnChain, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latestErr != nil {
		return OnChain{}, c.latestErr
	}
	if c.record == nil {
		return OnChain{}, nil
	}
	return OnChain{Exists: true, Key: *c.record, Signature: c.recordSig}, nil
}

func (c *fakeChain) Prepare(_ context.Context, _ [32]byte, key RevisionKey, sig []byte) (PreparedTx, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(sig) == 0 {
		return nil, errors.New("refusing to prepare an empty signature")
	}
	c.prepares++
	tx := fakeTx{hash: fmt.Sprintf("0xtx%d-cfg%x", c.prepares, key.ConfigHash[0])}
	c.prepared = append(c.prepared, tx)
	return tx, nil
}

func (c *fakeChain) Send(_ context.Context, p PreparedTx) (SendOutcome, error) {
	c.mu.Lock()
	c.sends++
	errFor, err, out := c.sendErrFor, c.sendErr, c.sendOut
	c.mu.Unlock()
	if errFor != nil {
		err = errFor(p)
	}
	if err != nil {
		return SendUnknown, err
	}
	return out, nil
}

func (c *fakeChain) Wait(_ context.Context, p PreparedTx) (WaitOutcome, error) {
	c.mu.Lock()
	c.waits++
	hook := c.onWait
	out := c.waitOut
	waitFor := c.waitFor
	c.mu.Unlock()
	if waitFor != nil {
		out = waitFor(p)
	}
	if hook != nil {
		hook(c, p)
	}
	return out, nil
}

func (c *fakeChain) setRecord(k RevisionKey, sig []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record = &k
	c.recordSig = sig
}

// --- helpers ----------------------------------------------------------------

func identity(name string) attest.WorkloadIdentityV2 {
	return attest.WorkloadIdentityV2{
		ClusterID: "prod-eu-1", APIVersion: "apps/v1", Kind: "Deployment",
		Namespace: "demo", Name: name,
	}
}

func desired(name string, cfgFill byte, uid string) Desired {
	var cfg [32]byte
	for i := range cfg {
		cfg[i] = cfgFill
	}
	return Desired{
		Identity: identity(name), Version: attest.V2,
		ConfigHash: cfg, UID: uid, Label: "demo/" + name,
	}
}

func newTestPublisher(t *testing.T) (*PublisherV2, *fakeChain, *fakeSigner) {
	t.Helper()
	s := newFakeSigner(t)
	c := &fakeChain{sendOut: SendAccepted, waitOut: WaitMinedSuccess}
	p, err := NewV2(s, c, logr.Discard())
	if err != nil {
		t.Fatalf("NewV2: %v", err)
	}
	return p, c, s
}

func mustID(t *testing.T, d Desired) [32]byte {
	t.Helper()
	id, err := d.Identity.WorkloadID()
	if err != nil {
		t.Fatalf("workload id: %v", err)
	}
	return id
}

// --- the rules --------------------------------------------------------------

func TestMinedSuccessConfirmsAndStops(t *testing.T) {
	p, c, s := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")
	if err := p.Enqueue(d); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	id := mustID(t, d)

	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process: %v", err)
	}
	if c.prepares != 1 || c.sends != 1 {
		t.Fatalf("prepares=%d sends=%d, want 1 each", c.prepares, c.sends)
	}

	// Re-enqueuing the same revision must do nothing at all.
	if err := p.Enqueue(d); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("second process: %v", err)
	}
	if c.prepares != 1 || s.calls != 1 {
		t.Errorf("a confirmed revision was worked again: prepares=%d signs=%d", c.prepares, s.calls)
	}
}

func TestUnknownKeepsTheAttempt(t *testing.T) {
	// Preparing a replacement after an unknown outcome is exactly what takes a
	// fresh nonce and publishes twice.
	p, c, s := newTestPublisher(t)
	c.waitOut = WaitUnknown
	d := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(d)
	id := mustID(t, d)

	for i := 0; i < 3; i++ {
		if _, err := p.process(context.Background(), id); err == nil {
			t.Fatal("an unknown outcome must not report success")
		}
	}
	if c.prepares != 1 {
		t.Errorf("prepared %d times across retries, want 1", c.prepares)
	}
	if s.calls != 1 {
		t.Errorf("signed %d times across retries, want 1", s.calls)
	}
	if c.sends != 3 {
		t.Errorf("sent %d times, want 3 -- retries must resend the same transaction", c.sends)
	}
}

func TestRevertedDiscardsTheAttempt(t *testing.T) {
	// A revert is definitive, so the spent transaction must be replaced.
	p, c, _ := newTestPublisher(t)
	c.waitOut = WaitReverted
	d := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(d)
	id := mustID(t, d)

	for i := 0; i < 2; i++ {
		if _, err := p.process(context.Background(), id); err == nil {
			t.Fatal("a revert must be reported as an error so backoff applies")
		}
	}
	if c.prepares != 2 {
		t.Errorf("prepared %d times, want 2 -- a reverted attempt is spent", c.prepares)
	}
}

func TestMatchingRecordConfirmsWithoutPublishing(t *testing.T) {
	// The pre-send query. Nothing may be prepared when the chain already holds
	// exactly this revision.
	p, c, s := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")
	c.setRecord(p.revisionKey(d), s.sign(t, p, d))
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err != nil {
		t.Fatalf("process: %v", err)
	}
	if c.prepares != 0 || c.sends != 0 || s.calls != 0 {
		t.Errorf("published over an identical existing record: prepares=%d sends=%d signs=%d",
			c.prepares, c.sends, s.calls)
	}
}

func TestDifferentRecordDoesNotConfirm(t *testing.T) {
	// A record for another incarnation, version or signer is NOT this revision.
	p, c, _ := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")

	otherDesired := desired("api", 0x11, "uid-DIFFERENT")
	other := p.revisionKey(otherDesired)
	c.setRecord(other, newFakeSigner(t).sign(t, p, otherDesired))
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err != nil {
		t.Fatalf("process: %v", err)
	}
	if c.prepares != 1 {
		t.Error("a record with a different incarnation was accepted as this revision")
	}
}

// --- the two decisive sequences ---------------------------------------------

// TestRestartDoesNotRepublish is the first sequence: send accepted, receipt
// lost, operator restarts, the record is on chain, nothing is published again.
func TestRestartDoesNotRepublish(t *testing.T) {
	s1 := newFakeSigner(t)
	chain := &fakeChain{sendOut: SendAccepted, waitOut: WaitUnknown}
	first, err := NewV2(s1, chain, logr.Discard())
	if err != nil {
		t.Fatalf("NewV2: %v", err)
	}

	d := desired("api", 0x11, "uid-1")
	_ = first.Enqueue(d)
	id := mustID(t, d)

	// The transaction is sent and mines, but the receipt never comes back.
	chain.onWait = func(c *fakeChain, _ PreparedTx) {
		c.setRecord(first.revisionKey(d), s1.sign(t, first, d))
	}
	if _, err := first.process(context.Background(), id); err != nil {
		// It reconciles immediately here; either way it must not have published
		// a second time.
		t.Logf("first publisher reported: %v", err)
	}
	sendsBefore := chain.sends
	preparesBefore := chain.prepares

	// Restart: a brand new publisher with no memory of the attempt, using the
	// same key so the fingerprint matches.
	chain.onWait = nil
	second, err := NewV2(&fakeSigner{key: s1.key, der: s1.der}, chain, logr.Discard())
	if err != nil {
		t.Fatalf("NewV2 after restart: %v", err)
	}
	_ = second.Enqueue(d)
	if _, err := second.process(context.Background(), id); err != nil {
		t.Fatalf("after restart: %v", err)
	}

	if chain.prepares != preparesBefore || chain.sends != sendsBefore {
		t.Errorf("republished after restart: prepares %d->%d sends %d->%d",
			preparesBefore, chain.prepares, sendsBefore, chain.sends)
	}
}

// TestNewRevisionSupersedesAnOldInFlightOne is the second sequence: A goes
// unknown, B arrives, A mines late, B is still what is wanted, and no later
// retry of A may overwrite it.
func TestNewRevisionSupersedesAnOldInFlightOne(t *testing.T) {
	p, c, sgn := newTestPublisher(t)
	c.waitOut = WaitUnknown

	revA := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(revA)
	id := mustID(t, revA)

	// A is attempted and its fate is unknown.
	if _, err := p.process(context.Background(), id); err == nil {
		t.Fatal("unknown must not report success")
	}
	keyA := p.revisionKey(revA)
	txA := c.prepared[0]

	// B arrives while A is in flight.
	revB := desired("api", 0x22, "uid-1")
	_ = p.Enqueue(revB)

	// A mines late. The chain now holds A, which is no longer desired.
	c.setRecord(keyA, sgn.sign(t, p, revA))
	c.waitOut = WaitMinedSuccess

	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("processing B: %v", err)
	}

	// B must have been prepared as a distinct transaction and published.
	if c.prepares < 2 {
		t.Fatalf("B was not prepared separately: prepares=%d", c.prepares)
	}
	txB := c.prepared[len(c.prepared)-1]
	if txB.Hash() == txA.Hash() {
		t.Fatal("B reused A's transaction; a superseded attempt must be discarded")
	}

	// And the state must record B, not A.
	p.mu.Lock()
	st := p.state[id]
	confirmed := st.confirmed
	wantKey := p.revisionKey(revB)
	p.mu.Unlock()
	if confirmed == nil || *confirmed != wantKey {
		t.Errorf("confirmed %v, want B's revision", confirmed)
	}

	// A late retry of A must not be able to publish: A is no longer desired,
	// so re-enqueuing it is a new revision decision, not a resurrection.
	preparesBefore := c.prepares
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("post-confirmation process: %v", err)
	}
	if c.prepares != preparesBefore {
		t.Error("a confirmed workload was published again")
	}
}

// --- rollback and supersession ---------------------------------------------
//
// "Already confirmed" describes the chain at the moment it was observed. Once a
// different revision has been desired, something may have been sent for it, so
// a confirmation from before that point no longer says what the chain holds.

// TestRollbackBeforeTheNewRevisionIsSent: A is confirmed, B is desired, and
// the Deployment returns to A before B is worked. B must not be published.
func TestRollbackBeforeTheNewRevisionIsSent(t *testing.T) {
	p, c, s := newTestPublisher(t)
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	id := mustID(t, revA)

	_ = p.Enqueue(revA)
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process A: %v", err)
	}
	// The chain holds A, as it would after a mined publish.
	c.setRecord(p.revisionKey(revA), s.sign(t, p, revA))

	_ = p.Enqueue(revB)
	_ = p.Enqueue(revA)

	preparesBefore, signsBefore := c.prepares, s.calls
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process after rollback: %v", err)
	}
	if c.prepares != preparesBefore || s.calls != signsBefore {
		t.Errorf("published after rolling back to the state already on chain: prepares %d->%d signs %d->%d",
			preparesBefore, c.prepares, signsBefore, s.calls)
	}

	p.mu.Lock()
	haveKey := p.state[id].key
	p.mu.Unlock()
	if haveKey != p.revisionKey(revA) {
		t.Error("the rollback to A was dropped; B is still desired")
	}
}

// TestRollbackAfterTheNewRevisionLanded: A is confirmed, B is sent with an
// unknown outcome and later mines, then the Deployment returns to A. The chain
// now holds B, so A must be published again.
func TestRollbackAfterTheNewRevisionLanded(t *testing.T) {
	p, c, s := newTestPublisher(t)
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	id := mustID(t, revA)

	_ = p.Enqueue(revA)
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process A: %v", err)
	}

	_ = p.Enqueue(revB)
	c.waitOut = WaitUnknown
	if _, err := p.process(context.Background(), id); err == nil {
		t.Fatal("unknown must not report success")
	}
	// B mines after its worker gave up waiting.
	c.setRecord(p.revisionKey(revB), s.sign(t, p, revB))
	c.waitOut = WaitMinedSuccess

	_ = p.Enqueue(revA)
	preparesBefore := c.prepares
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process after rollback: %v", err)
	}
	if c.prepares != preparesBefore+1 {
		t.Fatalf("A was not republished over B: prepares %d -> %d", preparesBefore, c.prepares)
	}

	p.mu.Lock()
	confirmed := p.state[id].confirmed
	p.mu.Unlock()
	if confirmed == nil || *confirmed != p.revisionKey(revA) {
		t.Errorf("confirmed %v, want A", confirmed)
	}
}

// TestRollbackWhileTheNewRevisionIsPending: A is on chain, B is sent and its
// outcome is unknown, the Deployment returns to A while B is still pending, and
// only then does B mine. The chain now holds B while the Deployment is A, so A
// must be published again within a few reconcile passes.
//
// Before T2 this failed: the rollback pass read A on chain and confirmed it,
// and a confirmed revision was not worked again, so the later B was never
// corrected.
//
// The test drives the real worker path, so it shows whether production would
// detect and correct the state. Work runs only if Enqueue
// (publisher_v2.go:275, publisher_v2.go:302) or processNext's own retry
// (publisher_v2.go:344, publisher_v2.go:348) queued it; process is never called
// directly and nothing is added to the queue by hand. The zero-backoff queue
// changes when a retry runs, not whether it is admitted. The explicit ordering
// lets B's retry run before B mines, after the rollback: being keyed by
// workload, it does A's step (publisher_v2.go:359) and confirms A from the
// stale read (publisher_v2.go:380-385).
func TestRollbackWhileTheNewRevisionIsPending(t *testing.T) {
	p, c, s := newTestPublisher(t)
	p.queue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(0, 0))
	defer p.queue.ShutDown()
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	keyA, keyB := p.revisionKey(revA), p.revisionKey(revB)
	id := mustID(t, revA)
	ctx := context.Background()
	sigA := s.sign(t, p, revA)

	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)
	if c.sends != 1 {
		t.Fatalf("setup: A was not published: sends %d", c.sends)
	}
	c.setRecord(keyA, sigA)

	// B is sent; its outcome is unknown and it has not mined yet.
	_ = p.Enqueue(revB)
	c.waitOut = WaitUnknown
	sendsBefore := c.sends
	drainQueue(ctx, p, 1)
	if c.sends != sendsBefore+1 {
		t.Fatalf("setup: B was not sent: sends %d -> %d", sendsBefore, c.sends)
	}
	if n := p.queue.Len(); n != 1 {
		t.Fatalf("setup: B's retry is not queued: queue length %d", n)
	}

	// Rollback to A while the chain still shows A. This also consumes B's
	// retry before B mines.
	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)

	// B mines now. A transaction prepared for A, if one is ever waited on,
	// writes A's record; any other transaction leaves the record alone.
	c.setRecord(keyB, s.sign(t, p, revB))
	c.waitOut = WaitMinedSuccess
	forA := fmt.Sprintf("cfg%x", keyA.ConfigHash[0])
	c.onWait = func(c *fakeChain, tx PreparedTx) {
		if strings.HasSuffix(tx.Hash(), forA) {
			c.setRecord(keyA, sigA)
		}
	}

	// The reconciler keeps observing A. Give it a bounded number of passes.
	const passes = 5
	preparesBefore, sendsAfterMine := c.prepares, c.sends
	processed := 0
	for i := 0; i < passes; i++ {
		_ = p.Enqueue(revA)
		processed += drainQueue(ctx, p, 10)
	}

	onchain, err := c.Latest(ctx, id)
	if err != nil || !onchain.Exists || onchain.Key != keyA || !p.recordIsOurs(revA, onchain.Signature) {
		p.mu.Lock()
		confirmed := p.state[id].confirmed
		p.mu.Unlock()
		holds := "nothing"
		switch {
		case err != nil:
			holds = "unreadable: " + err.Error()
		case onchain.Exists && onchain.Key == keyB:
			holds = "B"
		case onchain.Exists && onchain.Key == keyA:
			holds = "A with a signature that does not verify"
		case onchain.Exists:
			holds = "an unknown revision"
		}
		t.Fatalf("INVARIANT VIOLATED: Deployment is A but the chain holds %s after %d passes; "+
			"after B mined: prepares %d, sends %d, items processed %d; publisher confirmed A: %v",
			holds, passes, c.prepares-preparesBefore, c.sends-sendsAfterMine, processed,
			confirmed != nil && *confirmed == keyA)
	}
}

// drainQueue runs processNext while the publisher's queue has work, at most max
// times, and reports how many items it ran. Get blocks on an empty queue, so it
// is only called when Len reports something queued.
func drainQueue(ctx context.Context, p *PublisherV2, max int) int {
	n := 0
	for n < max && p.queue.Len() > 0 {
		p.processNext(ctx)
		n++
	}
	return n
}

// TestRevisionArrivingDuringSigningIsNotSent: B is desired while A is being
// signed. A's transaction must never be sent, because once sent it cannot be
// taken back.
func TestRevisionArrivingDuringSigningIsNotSent(t *testing.T) {
	p, c, s := newTestPublisher(t)
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	id := mustID(t, revA)
	_ = p.Enqueue(revA)

	s.onSign = func() {
		s.onSign = nil
		_ = p.Enqueue(revB)
	}
	again, err := p.process(context.Background(), id)
	if err != nil {
		t.Fatalf("process A: %v", err)
	}
	if c.sends != 0 {
		t.Fatalf("sent A after it was superseded: sends=%d", c.sends)
	}
	if !again {
		t.Fatal("A was superseded, but the publisher did not report more work")
	}

	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process B: %v", err)
	}
	if c.sends != 1 {
		t.Fatalf("sends=%d, want exactly B's", c.sends)
	}
	p.mu.Lock()
	confirmed := p.state[id].confirmed
	p.mu.Unlock()
	if confirmed == nil || *confirmed != p.revisionKey(revB) {
		t.Errorf("confirmed %v, want B", confirmed)
	}
}

// --- failure handling -------------------------------------------------------

func TestChainReadFailureIsRetryableAndPublishesNothing(t *testing.T) {
	p, c, s := newTestPublisher(t)
	c.latestErr = errors.New("rpc down")
	d := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err == nil {
		t.Fatal("an unreadable chain must not be treated as an absent record")
	}
	if c.prepares != 0 || s.calls != 0 {
		t.Error("published without being able to read the current record")
	}
}

func TestSendFaultIsAnErrorNotUncertainty(t *testing.T) {
	// Send returns an error only when nothing was sent at all. That must not be
	// confused with an unknown outcome.
	p, c, _ := newTestPublisher(t)
	c.sendErr = errors.New("no prepared transaction")
	d := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err == nil {
		t.Fatal("a send fault must surface")
	}
	if c.waits != 0 {
		t.Error("waited on a transaction that was never sent")
	}
}

func TestSigningFailureDoesNotPrepare(t *testing.T) {
	p, c, s := newTestPublisher(t)
	s.err = errors.New("kms denied")
	d := desired("api", 0x11, "uid-1")
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err == nil {
		t.Fatal("a signing failure must surface")
	}
	if c.prepares != 0 {
		t.Error("prepared a transaction without a signature")
	}
}

func TestEnqueueRejectsAnIdentityWithoutCluster(t *testing.T) {
	// An empty ClusterID would reintroduce the cross-cluster collision, so it
	// must fail loudly at the boundary rather than produce a workload id.
	p, _, _ := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")
	d.Identity.ClusterID = ""
	if err := p.Enqueue(d); err == nil {
		t.Fatal("an identity with no cluster was accepted")
	}
}

// TestRevisionArrivingMidFlightIsNotLost covers the window that
// TestNewRevisionSupersedesAnOldInFlightOne does not: a new revision enqueued
// while a worker is already waiting on the previous one.
//
// The worker snapshots the desired revision when it starts, so from its point
// of view nothing changed. When its transaction then mines, it is confirming a
// revision that is no longer wanted. It must say so rather than clear the
// state, or the newer revision would be dropped and never published.
//
// This is the concurrency window that the seq comparison in confirm exists for.
// Without that comparison this test fails.
func TestRevisionArrivingMidFlightIsNotLost(t *testing.T) {
	p, c, _ := newTestPublisher(t)

	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	id := mustID(t, revA)
	_ = p.Enqueue(revA)

	// B arrives while A's transaction is being waited on, which is exactly what
	// a reconcile does mid-publish.
	// Wait releases the fake's lock before invoking the hook, so this must not
	// touch it.
	c.onWait = func(_ *fakeChain, _ PreparedTx) { _ = p.Enqueue(revB) }

	again, err := p.process(context.Background(), id)
	if err != nil {
		t.Fatalf("process A: %v", err)
	}
	if !again {
		t.Fatal("A confirmed while B was already desired, but the publisher did not report more work")
	}

	// The state must still want B, and must not be holding A's transaction.
	p.mu.Lock()
	st := p.state[id]
	wantB := p.revisionKey(revB)
	haveKey, havePrepared := st.key, st.prepared
	p.mu.Unlock()
	if haveKey != wantB {
		t.Error("the desired revision was overwritten by the in-flight one")
	}
	if havePrepared != nil {
		t.Error("A's prepared transaction was retained for B; it would publish the wrong state")
	}

	// Working the queue again must publish B.
	c.onWait = nil
	preparesBefore := c.prepares
	if _, err := p.process(context.Background(), id); err != nil {
		t.Fatalf("process B: %v", err)
	}
	if c.prepares != preparesBefore+1 {
		t.Errorf("B was not published: prepares %d -> %d", preparesBefore, c.prepares)
	}
}

// --- reconciliation verifies, it does not merely compare --------------------
//
// A record carries the fingerprint its WRITER chose. Matching fields therefore
// prove only that somebody claimed our key, which is why confirmation requires
// the signature to verify against the envelope we would have signed.

// TestRecordWithForeignSignatureIsNotConfirmed is the attack the field
// comparison alone would miss: an account able to write puts our fingerprint
// next to a signature we did not make.
//
// Without verification the operator would mark the workload confirmed and stop
// publishing, leaving it looking attested while pod-verify reports FAIL.
func TestRecordWithForeignSignatureIsNotConfirmed(t *testing.T) {
	p, c, s := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")

	// Every field matches. The signature is from a different key.
	impostor := newFakeSigner(t)
	c.setRecord(p.revisionKey(d), impostor.sign(t, p, d))
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err != nil {
		t.Fatalf("process: %v", err)
	}
	if c.prepares != 1 || s.calls != 1 {
		t.Errorf("a record signed by another key was accepted as ours: prepares=%d signs=%d",
			c.prepares, s.calls)
	}
}

// TestRecordWithMalformedSignatureIsNotConfirmed covers the cheaper version of
// the same attack: matching fields with bytes that are not a signature at all,
// including none.
func TestRecordWithMalformedSignatureIsNotConfirmed(t *testing.T) {
	for name, sig := range map[string][]byte{
		"empty":     {},
		"nil":       nil,
		"garbage":   {0x30, 0x45, 0x02, 0x01, 0x00},
		"truncated": {0x30},
	} {
		t.Run(name, func(t *testing.T) {
			p, c, _ := newTestPublisher(t)
			d := desired("api", 0x11, "uid-1")
			c.setRecord(p.revisionKey(d), sig)
			_ = p.Enqueue(d)

			if _, err := p.process(context.Background(), mustID(t, d)); err != nil {
				t.Fatalf("process: %v", err)
			}
			if c.prepares != 1 {
				t.Errorf("a record with a %s signature was accepted", name)
			}
		})
	}
}

// TestSignatureOverDifferentContentIsNotConfirmed is the tampering case.
//
// The signature is genuine and from our own key, but it was made over a
// different envelope. The digest therefore differs and verification fails, so a
// record cannot be assembled from a signature harvested elsewhere.
func TestSignatureOverDifferentContentIsNotConfirmed(t *testing.T) {
	cases := map[string]func(Desired) Desired{
		"different UID": func(d Desired) Desired {
			d.UID = "uid-SOMETHING-ELSE"
			return d
		},
		"different namespace": func(d Desired) Desired {
			d.Identity.Namespace = "other"
			return d
		},
		"different cluster": func(d Desired) Desired {
			d.Identity.ClusterID = "another-cluster"
			return d
		},
		"different config hash": func(d Desired) Desired {
			d.ConfigHash[0] ^= 0xff
			return d
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, c, s := newTestPublisher(t)
			want := desired("api", 0x11, "uid-1")

			// Sign a DIFFERENT envelope with the right key, then file it under
			// the key fields of the revision we want.
			harvested := s.sign(t, p, mutate(want))
			c.setRecord(p.revisionKey(want), harvested)
			signsBefore := s.calls
			_ = p.Enqueue(want)

			if _, err := p.process(context.Background(), mustID(t, want)); err != nil {
				t.Fatalf("process: %v", err)
			}
			if c.prepares != 1 || s.calls != signsBefore+1 {
				t.Errorf("a signature over %s was accepted for this revision", name)
			}
		})
	}
}

// TestValidRecordConfirmsWithoutTouchingKMS states the other half: when the
// signature does verify, nothing is signed and nothing is published. This is
// what makes a restart cheap instead of a fresh KMS call per workload.
func TestValidRecordConfirmsWithoutTouchingKMS(t *testing.T) {
	p, c, s := newTestPublisher(t)
	d := desired("api", 0x11, "uid-1")
	c.setRecord(p.revisionKey(d), s.sign(t, p, d))
	signsBefore := s.calls
	_ = p.Enqueue(d)

	if _, err := p.process(context.Background(), mustID(t, d)); err != nil {
		t.Fatalf("process: %v", err)
	}
	if s.calls != signsBefore {
		t.Errorf("called KMS %d times to confirm a record it could verify locally", s.calls-signsBefore)
	}
	if c.prepares != 0 || c.sends != 0 {
		t.Errorf("published over a valid record: prepares=%d sends=%d", c.prepares, c.sends)
	}
}

// TestNewV2RejectsAnUnparseableSignerKey pins that a bad key fails at
// construction rather than at the first publication.
func TestNewV2RejectsAnUnparseableSignerKey(t *testing.T) {
	bad := &fakeSigner{der: []byte("not a DER public key")}
	if _, err := NewV2(bad, &fakeChain{}, logr.Discard()); err == nil {
		t.Fatal("a signer whose public key cannot be parsed was accepted")
	}
}

// --- rollback while a transaction is unresolved ------------------------------
//
// These drive the real worker path the way TestRollbackWhileTheNewRevisionIsPending
// does: work runs only if Enqueue or processNext's own retry queued it, on a
// queue whose backoff is zero. The zero backoff changes when a retry runs, not
// whether it is admitted.

// TestRollbackRecoversWithoutFurtherEnqueue: A is on chain, B is sent with an
// unknown outcome, the Deployment returns to A, and B mines afterwards. The
// reconciler enqueues only on Deployment events, so after B mines nothing is
// enqueued at all. The publisher must still put A back on chain, and then stop.
func TestRollbackRecoversWithoutFurtherEnqueue(t *testing.T) {
	p, c, s := newTestPublisher(t)
	p.queue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(0, 0))
	defer p.queue.ShutDown()
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	keyA, keyB := p.revisionKey(revA), p.revisionKey(revB)
	id := mustID(t, revA)
	ctx := context.Background()
	sigA := s.sign(t, p, revA)

	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)
	if c.sends != 1 {
		t.Fatalf("setup: A was not published: sends %d", c.sends)
	}
	c.setRecord(keyA, sigA)

	// B is sent; its outcome is unknown and it has not mined yet.
	_ = p.Enqueue(revB)
	c.waitOut = WaitUnknown
	drainQueue(ctx, p, 1)
	if c.sends != 2 {
		t.Fatalf("setup: B was not sent: sends %d", c.sends)
	}
	if n := p.queue.Len(); n != 1 {
		t.Fatalf("setup: B's retry is not queued: queue length %d", n)
	}

	// Rollback while the chain still shows A. B's retry runs here, before B
	// mines, and A is confirmed from that stale read.
	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)

	// B mines. A transaction for A writes A's record when waited on.
	c.setRecord(keyB, s.sign(t, p, revB))
	c.waitOut = WaitMinedSuccess
	forA := fmt.Sprintf("cfg%x", keyA.ConfigHash[0])
	c.onWait = func(c *fakeChain, tx PreparedTx) {
		if strings.HasSuffix(tx.Hash(), forA) {
			c.setRecord(keyA, sigA)
		}
	}

	// No Enqueue from here on: only what the publisher queued itself runs.
	const rounds, perRound = 5, 10
	holdsA := func() bool {
		oc, err := c.Latest(ctx, id)
		return err == nil && oc.Exists && oc.Key == keyA && p.recordIsOurs(revA, oc.Signature)
	}
	processed := 0
	for i := 0; i < rounds && !holdsA(); i++ {
		processed += drainQueue(ctx, p, perRound)
	}
	if !holdsA() {
		oc, _ := c.Latest(ctx, id)
		t.Fatalf("LIVENESS VIOLATED: Deployment is A but after B mined the chain holds B=%v "+
			"with no further Enqueue; items processed %d, queue length %d",
			oc.Exists && oc.Key == keyB, processed, p.queue.Len())
	}

	// Everything is resolved, so the retries must stop.
	for i := 0; i < rounds && p.queue.Len() > 0; i++ {
		drainQueue(ctx, p, perRound)
	}
	if n := p.queue.Len(); n != 0 {
		t.Fatalf("NO TERMINATION: the chain holds A and nothing is unresolved, but the queue still has %d item(s) after %d rounds",
			n, rounds)
	}
}

// TestRollbackFlapPublishesOnce: A1 is sent (unknown), B1 is sent (unknown),
// and the Deployment returns to A. Exactly one transaction may be live for A at
// a time: A1 is still unresolved when A is desired again, so it is reused
// rather than replaced. Phase 1 checks that while nothing mines; phase 2 lets
// A1 mine and then B1 over it, after which at most one new A transaction may be
// prepared and the chain must end on A.
func TestRollbackFlapPublishesOnce(t *testing.T) {
	p, c, s := newTestPublisher(t)
	p.queue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(0, 0))
	defer p.queue.ShutDown()
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	keyA, keyB := p.revisionKey(revA), p.revisionKey(revB)
	id := mustID(t, revA)
	ctx := context.Background()
	sigA := s.sign(t, p, revA)
	forA := fmt.Sprintf("cfg%x", keyA.ConfigHash[0])
	isA := func(tx PreparedTx) bool { return strings.HasSuffix(tx.Hash(), forA) }
	duplicate := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("DUPLICATE PUBLICATION: "+format, args...)
	}

	c.waitOut = WaitUnknown
	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 1)
	if c.prepares != 1 || c.sends != 1 {
		t.Fatalf("setup: A1 was not sent: prepares %d sends %d", c.prepares, c.sends)
	}
	txA1 := c.prepared[0]

	_ = p.Enqueue(revB)
	drainQueue(ctx, p, 1)
	if c.prepares != 2 || c.sends != 2 {
		t.Fatalf("setup: B1 was not sent: prepares %d sends %d", c.prepares, c.sends)
	}
	txB1 := c.prepared[1]

	// Phase 1: back to A. Nothing mines and every wait is unknown, so A1 is
	// unresolved throughout and no other A transaction may be prepared.
	preparedBeforeSecondA := c.prepares
	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)
	if c.prepares != preparedBeforeSecondA {
		duplicate("prepares %d -> %d while A1 %s was unresolved; prepared %v",
			preparedBeforeSecondA, c.prepares, txA1.Hash(), c.prepared[preparedBeforeSecondA:])
	}

	// Phase 2: A1 mines, writing A's record once on its first mined wait. B1
	// mines after it, over A: it stays unknown until A1 has mined, then writes
	// B. Any later A transaction writes A's record when it mines.
	a1Mined := false
	c.waitFor = func(tx PreparedTx) WaitOutcome {
		switch {
		case tx.Hash() == txA1.Hash():
			if !a1Mined {
				a1Mined = true
				c.setRecord(keyA, sigA)
			}
		case tx.Hash() == txB1.Hash():
			if !a1Mined {
				return WaitUnknown
			}
			c.setRecord(keyB, s.sign(t, p, revB))
		case isA(tx):
			c.setRecord(keyA, sigA)
		}
		return WaitMinedSuccess
	}
	for i := 0; i < 5; i++ {
		_ = p.Enqueue(revA)
		drainQueue(ctx, p, 10)
	}

	var newA []string
	for _, tx := range c.prepared[preparedBeforeSecondA:] {
		if isA(tx) {
			newA = append(newA, tx.Hash())
		}
	}
	oc, err := c.Latest(ctx, id)
	holdsA := err == nil && oc.Exists && oc.Key == keyA && p.recordIsOurs(revA, oc.Signature)
	if len(newA) > 1 || !holdsA {
		duplicate("%d transactions prepared for the second desired A %v, want at most 1 "+
			"(A1 %s was unresolved when A was desired again); chain holds A: %v",
			len(newA), newA, txA1.Hash(), holdsA)
	}
}

// TestRollbackWithUnresolvedTxDoesNotRepublish: the Deployment returns to A
// while B's transaction is unknown, and B never mines: the chain keeps showing
// A. Nothing may be published for A, B must not be resent, and B's handle
// must not be dropped: it keeps being checked.
func TestRollbackWithUnresolvedTxDoesNotRepublish(t *testing.T) {
	p, c, s := newTestPublisher(t)
	p.queue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(0, 0))
	defer p.queue.ShutDown()
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	keyA := p.revisionKey(revA)
	id := mustID(t, revA)
	ctx := context.Background()

	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 10)
	if c.sends != 1 {
		t.Fatalf("setup: A was not published: sends %d", c.sends)
	}
	c.setRecord(keyA, s.sign(t, p, revA))

	_ = p.Enqueue(revB)
	c.waitOut = WaitUnknown
	drainQueue(ctx, p, 1)
	if c.sends != 2 {
		t.Fatalf("setup: B was not sent: sends %d", c.sends)
	}
	txB := c.prepared[len(c.prepared)-1]

	var waited []string
	c.onWait = func(_ *fakeChain, tx PreparedTx) { waited = append(waited, tx.Hash()) }

	preparesAtRollback, sendsAtRollback := c.prepares, c.sends
	const rounds = 20
	checkedB := false
	// The rollback is enqueued once. Every later round only drains, so any
	// work it finds was queued by the publisher's own retry.
	_ = p.Enqueue(revA)
	for i := 0; i < rounds; i++ {
		waited = waited[:0]
		drainQueue(ctx, p, 10)
		checkedB = false
		for _, h := range waited {
			checkedB = checkedB || h == txB.Hash()
		}
	}

	oc, err := c.Latest(ctx, id)
	holdsA := err == nil && oc.Exists && oc.Key == keyA
	if c.prepares != preparesAtRollback || c.sends != sendsAtRollback || !checkedB || p.queue.Len() == 0 || !holdsA {
		t.Fatalf("UNRESOLVED TX VIOLATED: after %d rounds with B unknown: prepares %d -> %d, sends %d -> %d, "+
			"B (%s) re-checked in the last round: %v, re-check still queued: %v, chain holds A: %v",
			rounds, preparesAtRollback, c.prepares, sendsAtRollback, c.sends,
			txB.Hash(), checkedB, p.queue.Len() > 0, holdsA)
	}
}

// TestResendFaultStillReadsTheReceipt: A1 is sent (unknown), B1 is sent
// (unknown), and the Deployment returns to A, which adopts A1. Then both have
// mined, A1 first and B1 over it, so the chain holds B. The node no longer
// accepts A1, so every resend of it fails with "nothing was sent". That error
// says nothing about the earlier send: A1's receipt must still be read, after
// which exactly one new A transaction puts A back, without any further Enqueue.
func TestResendFaultStillReadsTheReceipt(t *testing.T) {
	p, c, s := newTestPublisher(t)
	p.queue = workqueue.NewRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(0, 0))
	defer p.queue.ShutDown()
	revA := desired("api", 0x11, "uid-1")
	revB := desired("api", 0x22, "uid-1")
	keyA, keyB := p.revisionKey(revA), p.revisionKey(revB)
	id := mustID(t, revA)
	ctx := context.Background()
	sigA := s.sign(t, p, revA)
	forA := fmt.Sprintf("cfg%x", keyA.ConfigHash[0])
	isA := func(tx PreparedTx) bool { return strings.HasSuffix(tx.Hash(), forA) }

	c.waitOut = WaitUnknown
	_ = p.Enqueue(revA)
	drainQueue(ctx, p, 1)
	if c.prepares != 1 || c.sends != 1 {
		t.Fatalf("setup: A1 was not sent: prepares %d sends %d", c.prepares, c.sends)
	}
	txA1 := c.prepared[0]
	_ = p.Enqueue(revB)
	drainQueue(ctx, p, 1)
	if c.prepares != 2 || c.sends != 2 {
		t.Fatalf("setup: B1 was not sent: prepares %d sends %d", c.prepares, c.sends)
	}

	// The last Enqueue: A is desired again and adopts A1.
	_ = p.Enqueue(revA)
	p.mu.Lock()
	adopted := p.state[id].prepared
	p.mu.Unlock()
	if adopted == nil || adopted.Hash() != txA1.Hash() {
		t.Fatalf("setup: A1 was not adopted as A's attempt: %v", adopted)
	}

	c.setRecord(keyB, s.sign(t, p, revB))
	resendFailed, receiptAfterFault := false, false
	c.sendErrFor = func(tx PreparedTx) error {
		if tx.Hash() == txA1.Hash() {
			resendFailed = true
			return errors.New("no transaction was sent")
		}
		return nil
	}
	c.waitFor = func(tx PreparedTx) WaitOutcome {
		switch {
		case tx.Hash() == txA1.Hash():
			receiptAfterFault = receiptAfterFault || resendFailed
		case isA(tx):
			c.setRecord(keyA, sigA)
		}
		return WaitMinedSuccess
	}
	preparesBefore := c.prepares

	const rounds, perRound = 5, 10
	for i := 0; i < rounds && p.queue.Len() > 0; i++ {
		drainQueue(ctx, p, perRound)
	}

	var newA []string
	for _, tx := range c.prepared[preparesBefore:] {
		if isA(tx) {
			newA = append(newA, tx.Hash())
		}
	}
	oc, err := c.Latest(ctx, id)
	holdsA := err == nil && oc.Exists && oc.Key == keyA && p.recordIsOurs(revA, oc.Signature)
	if !receiptAfterFault || len(newA) != 1 || !holdsA {
		t.Fatalf("RESEND FAULT: A1 %s resend failed: %v, receipt read after that: %v; "+
			"new A transactions %v, want exactly 1; chain holds A: %v; queue length %d",
			txA1.Hash(), resendFailed, receiptAfterFault, newA, holdsA, p.queue.Len())
	}
}
