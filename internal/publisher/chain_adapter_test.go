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
	"errors"
	"testing"

	"github.com/franklin1014/proof-of-deploy/internal/chain"
)

type fakeClientV2 struct {
	att      chain.AttestationV2
	sendRes  chain.SendResult
	waitRes  chain.PublishResult
	prepared struct {
		version                       uint16
		cfg, incarnation, fingerprint [32]byte
	}
}

func (f *fakeClientV2) LatestAttestation(context.Context, [32]byte) (chain.AttestationV2, error) {
	return f.att, nil
}

func (f *fakeClientV2) Prepare(_ context.Context, _ [32]byte, v uint16, cfg, inc [32]byte, _ []byte, fp [32]byte) (*chain.PreparedPublish, error) {
	f.prepared.version, f.prepared.cfg, f.prepared.incarnation, f.prepared.fingerprint = v, cfg, inc, fp
	return &chain.PreparedPublish{}, nil
}

func (f *fakeClientV2) Send(context.Context, *chain.PreparedPublish) (chain.SendResult, error) {
	return f.sendRes, nil
}

func (f *fakeClientV2) Wait(context.Context, *chain.PreparedPublish) chain.PublishResult {
	return f.waitRes
}

// TestAdapterKeepsFieldsInPlace pins the field mapping in both directions.
// Four 32-byte values travel side by side, so a transposition would still
// compile and would only show up as a workload that never confirms.
func TestAdapterKeepsFieldsInPlace(t *testing.T) {
	cfg, inc, fp := [32]byte{1}, [32]byte{2}, [32]byte{3}
	f := &fakeClientV2{att: chain.AttestationV2{
		ConfigHash: cfg, Incarnation: inc, SignerFingerprint: fp,
		HashVersion: 2, Signature: []byte{9}, Exists: true,
	}}
	a := NewChainV2(f)

	got, err := a.Latest(context.Background(), [32]byte{})
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	want := RevisionKey{Version: 2, ConfigHash: cfg, Incarnation: inc, Fingerprint: fp}
	if !got.Exists || got.Key != want || string(got.Signature) != "\x09" {
		t.Fatalf("latest mapped to %+v, want key %+v", got, want)
	}

	if _, err := a.Prepare(context.Background(), [32]byte{}, want, []byte{9}); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if f.prepared.version != 2 || f.prepared.cfg != cfg || f.prepared.incarnation != inc || f.prepared.fingerprint != fp {
		t.Fatalf("prepare received %+v, want the key's fields in place", f.prepared)
	}
}

func TestAdapterAbsentRecordIsNotExists(t *testing.T) {
	a := NewChainV2(&fakeClientV2{})
	got, err := a.Latest(context.Background(), [32]byte{})
	if err != nil || got.Exists {
		t.Fatalf("absent record mapped to %+v, %v", got, err)
	}
}

func TestAdapterOutcomes(t *testing.T) {
	cases := []struct {
		send     chain.SubmitOutcome
		wait     chain.PublishOutcome
		wantSend SendOutcome
		wantWait WaitOutcome
	}{
		{chain.SubmitAccepted, chain.OutcomeMinedSuccess, SendAccepted, WaitMinedSuccess},
		{chain.SubmitUnknown, chain.OutcomeReverted, SendUnknown, WaitReverted},
		{chain.SubmitUnknown, chain.OutcomeUnknown, SendUnknown, WaitUnknown},
	}
	for _, tc := range cases {
		f := &fakeClientV2{
			// A transport cause must not turn uncertainty into an error.
			sendRes: chain.SendResult{Outcome: tc.send, Cause: errors.New("connection reset")},
			waitRes: chain.PublishResult{Outcome: tc.wait},
		}
		a := NewChainV2(f)
		s, err := a.Send(context.Background(), &chain.PreparedPublish{})
		if err != nil || s != tc.wantSend {
			t.Errorf("send %v mapped to %v, %v; want %v", tc.send, s, err, tc.wantSend)
		}
		w, err := a.Wait(context.Background(), &chain.PreparedPublish{})
		if err != nil || w != tc.wantWait {
			t.Errorf("wait %v mapped to %v, %v; want %v", tc.wait, w, err, tc.wantWait)
		}
	}
}

func TestAdapterRejectsForeignHandle(t *testing.T) {
	a := NewChainV2(&fakeClientV2{})
	if _, err := a.Send(context.Background(), fakeTx{hash: "0x1"}); err == nil {
		t.Fatal("a handle from another backend was accepted")
	}
}
