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
	"sync"
	"testing"

	"github.com/go-logr/logr"

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

func (c *fakeChain) Send(_ context.Context, _ PreparedTx) (SendOutcome, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sends++
	if c.sendErr != nil {
		return SendUnknown, c.sendErr
	}
	return c.sendOut, nil
}

func (c *fakeChain) Wait(_ context.Context, p PreparedTx) (WaitOutcome, error) {
	c.mu.Lock()
	c.waits++
	hook := c.onWait
	out := c.waitOut
	c.mu.Unlock()
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
