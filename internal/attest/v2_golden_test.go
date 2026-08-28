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

package attest

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Golden vectors for the v2 wire encoding.
//
// The expected values in this file were NOT produced by running the code under
// test. They were computed by a separate implementation written from the layout
// documented in identity.go and envelope.go (see
// docs/adr/0002-v2-encoding-and-verifier-contract.md). Two implementations
// agreeing is evidence the spec is unambiguous; a test that hashes with the
// same function it is checking proves only that the function is deterministic.
//
// If a change here makes these fail, that is a PROTOCOL CHANGE, not a
// refactor. Every signature ever produced becomes unverifiable. Bump the
// version and add a new vector set; do not update these numbers.

const (
	// The config hash used throughout is the real v1 benign/tampered collision
	// from testdata/08 and 09 -- the hash that demonstrates why v2 exists.
	goldenConfigHashHex = "89ab57526b689c52761431af4bc5451933c1947b74e0db262438ad1881c17a77"
	goldenUID           = "1f8b4c2e-7a3d-4e5f-9c1b-2d3e4f5a6b7c"

	// v2 is referenced as a literal rather than a named constant: this file
	// pins the encoding before v2 is declared supported.
	v2 Version = 2
)

func goldenConfigHash(t *testing.T) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(goldenConfigHashHex)
	if err != nil {
		t.Fatalf("decode golden config hash: %v", err)
	}
	var h [32]byte
	copy(h[:], b)
	return h
}

func baseIdentity() WorkloadIdentityV2 {
	return WorkloadIdentityV2{
		ClusterID:  "prod-eu-1",
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Namespace:  "payments",
		Name:       "api",
	}
}

func mustWorkloadID(t *testing.T, w WorkloadIdentityV2) string {
	t.Helper()
	id, err := w.WorkloadID()
	if err != nil {
		t.Fatalf("WorkloadID(%s): %v", w, err)
	}
	return hex.EncodeToString(id[:])
}

func mustDigest(t *testing.T, e EnvelopeV2) string {
	t.Helper()
	d, err := e.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest: %v", err)
	}
	return hex.EncodeToString(d[:])
}

func TestWorkloadIDGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   WorkloadIdentityV2
		want string
	}{
		{
			name: "baseline",
			id:   baseIdentity(),
			want: "ca4d441b3a529b179d9219ef6bcddccd868822fc391ed52089ae734942699846",
		},
		{
			// The v1 defect this type exists to fix: same namespace/name in a
			// different cluster must not occupy the same on-chain slot.
			name: "same workload, different cluster",
			id: WorkloadIdentityV2{
				ClusterID: "prod-us-1", APIVersion: "apps/v1",
				Kind: "Deployment", Namespace: "payments", Name: "api",
			},
			want: "94b0200f97c9f40cc37a6c81aaa593564831160b0835d76974cd100640c8ce25",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustWorkloadID(t, tc.id); got != tc.want {
				t.Errorf("WorkloadID changed.\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestIdentityEncodingIsInjective is the reason this vector set exists.
//
// v1 built its identifier as SHA-256(namespace + "/" + name), which is not
// injective on arbitrary strings: {"a/b", "c"} and {"a", "b/c"} produce
// identical bytes. v1 is safe only because Kubernetes forbids "/" in names --
// the guarantee rests on an invariant enforced somewhere else entirely.
//
// Length prefixing makes the encoding injective by construction, so the
// guarantee no longer depends on anyone else's validation rules.
func TestIdentityEncodingIsInjective(t *testing.T) {
	a := WorkloadIdentityV2{ClusterID: "prod-eu-1", APIVersion: "apps/v1", Kind: "Deployment", Namespace: "a/b", Name: "c"}
	b := WorkloadIdentityV2{ClusterID: "prod-eu-1", APIVersion: "apps/v1", Kind: "Deployment", Namespace: "a", Name: "b/c"}

	gotA, gotB := mustWorkloadID(t, a), mustWorkloadID(t, b)
	if gotA == gotB {
		t.Fatalf("identities {a/b, c} and {a, b/c} collide: %s\n"+
			"the encoding is not injective and has reintroduced the v1 defect", gotA)
	}
	if want := "b939e9ddaa0225dc1c9b2dd73932ee08d95b4ad080a020678844f2952340d4ea"; gotA != want {
		t.Errorf("{a/b, c}: got %s want %s", gotA, want)
	}
	if want := "6ac993f5c172192c9e515c4c60a35e60ff5bf0792d49af63a340c2cdc5833f27"; gotB != want {
		t.Errorf("{a, b/c}: got %s want %s", gotB, want)
	}

	// The same must hold once the identity is nested inside an envelope.
	ch := goldenConfigHash(t)
	dA := mustDigest(t, EnvelopeV2{Version: v2, Identity: a, UID: goldenUID, ConfigHash: ch})
	dB := mustDigest(t, EnvelopeV2{Version: v2, Identity: b, UID: goldenUID, ConfigHash: ch})
	if dA == dB {
		t.Error("ambiguous identities collide inside the signed envelope")
	}
}

func TestSigningDigestGoldenVectors(t *testing.T) {
	ch := goldenConfigHash(t)
	for _, tc := range []struct {
		name string
		env  EnvelopeV2
		want string
	}{
		{
			name: "uid present",
			env:  EnvelopeV2{Version: v2, Identity: baseIdentity(), UID: goldenUID, ConfigHash: ch},
			want: "f2ab0382d3bb00cb75c9663144e032571ac2e54341be333f48a9c2acd7a5c47a",
		},
		{
			name: "uid absent",
			env:  EnvelopeV2{Version: v2, Identity: baseIdentity(), UID: "", ConfigHash: ch},
			want: "50ded3aa94df82c73817f439744515d08abefa863f9b09a6129d24b924fcff7a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustDigest(t, tc.env); got != tc.want {
				t.Errorf("SigningDigest changed -- this invalidates every signature.\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestSigningPreimageIsPinned pins the bytes, not just the digest. Without it a
// layout change that happened to produce a colliding digest would be invisible,
// and the preimage is what a second implementation has to reproduce.
func TestSigningPreimageIsPinned(t *testing.T) {
	env := EnvelopeV2{Version: v2, Identity: baseIdentity(), UID: goldenUID, ConfigHash: goldenConfigHash(t)}
	pre, err := env.SigningPreimage()
	if err != nil {
		t.Fatalf("SigningPreimage: %v", err)
	}
	const want = "70726f6f662d6f662d6465706c6f792f6174746573746174696f6e2f76320000" +
		"020000005e70726f6f662d6f662d6465706c6f792f776f726b6c6f61642d6964" +
		"656e746974792f7632000000000970726f642d65752d3100000007617070732f" +
		"76310000000a4465706c6f796d656e74000000087061796d656e747300000003" +
		"6170690000002431663862346332652d376133642d346535662d396331622d32" +
		"643365346635613662376389ab57526b689c52761431af4bc5451933c1947b74" +
		"e0db262438ad1881c17a77"
	if got := hex.EncodeToString(pre); got != want {
		t.Errorf("signing preimage layout changed.\n got: %s\nwant: %s", got, want)
	}
	if len(pre) != 203 {
		t.Errorf("preimage length = %d, want 203", len(pre))
	}
}

// TestUIDIsBoundBySignature is the security property ADR 0001 Decision 2 exists
// for. Storing a UID on-chain without signing it is worth nothing: a
// compromised publisher EOA could pair a valid KMS signature with a different
// incarnation, defeating the separation between the account that writes and the
// key that attests.
func TestUIDIsBoundBySignature(t *testing.T) {
	ch := goldenConfigHash(t)
	base := baseIdentity()

	withUID := mustDigest(t, EnvelopeV2{Version: v2, Identity: base, UID: goldenUID, ConfigHash: ch})
	without := mustDigest(t, EnvelopeV2{Version: v2, Identity: base, UID: "", ConfigHash: ch})
	other := mustDigest(t, EnvelopeV2{Version: v2, Identity: base, UID: "00000000-0000-0000-0000-000000000001", ConfigHash: ch})

	if withUID == without {
		t.Error("an envelope with a UID signs the same as one without: incarnation is not bound")
	}
	if withUID == other {
		t.Error("two different UIDs sign identically: incarnation is not bound")
	}
}

// TestClusterIDIsBoundBySignature is the same argument for cluster identity.
// Without it a valid signature could be re-filed against another cluster's slot.
func TestClusterIDIsBoundBySignature(t *testing.T) {
	ch := goldenConfigHash(t)
	eu := baseIdentity()
	us := baseIdentity()
	us.ClusterID = "prod-us-1"

	if mustWorkloadID(t, eu) == mustWorkloadID(t, us) {
		t.Error("clusters share an on-chain key: the v1 cross-cluster collision is back")
	}
	a := mustDigest(t, EnvelopeV2{Version: v2, Identity: eu, UID: goldenUID, ConfigHash: ch})
	b := mustDigest(t, EnvelopeV2{Version: v2, Identity: us, UID: goldenUID, ConfigHash: ch})
	if a == b {
		t.Error("the same workload in two clusters signs identically: clusterID is not bound")
	}
}

// TestVersionIsBoundBySignature preserves the property v1 already has: altering
// the stored version breaks the signature rather than selecting a different
// normalizer and recomputing the wrong way.
func TestVersionIsBoundBySignature(t *testing.T) {
	ch := goldenConfigHash(t)
	id := baseIdentity()
	one := mustDigest(t, EnvelopeV2{Version: V1, Identity: id, UID: goldenUID, ConfigHash: ch})
	two := mustDigest(t, EnvelopeV2{Version: v2, Identity: id, UID: goldenUID, ConfigHash: ch})
	if one == two {
		t.Fatal("the protocol version is not bound by the signature")
	}
	if want := "86165cad805f4e16d712830ca096662067980ca28483fd3e2afefaf20a08e213"; one != want {
		t.Errorf("version-1 envelope digest: got %s want %s", one, want)
	}
}

// TestDomainsAreSeparated: a workload ID and a signing digest must never be
// interchangeable, or a value computed for one could be accepted as the other.
func TestDomainsAreSeparated(t *testing.T) {
	id := baseIdentity()
	wid := mustWorkloadID(t, id)
	dig := mustDigest(t, EnvelopeV2{Version: v2, Identity: id, UID: goldenUID, ConfigHash: goldenConfigHash(t)})
	if wid == dig {
		t.Error("workload ID and signing digest collide: domains are not separated")
	}

	var env EnvelopeV2
	if got := hex.EncodeToString(env.Incarnation()[:]); got != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("empty UID must map to the all-zero incarnation, got %s", got)
	}
	withUID := EnvelopeV2{UID: goldenUID}
	if want := "cc04bd74d9e1fc9a448bda7f8b296a39cf8027fda4209dd7dc12a3d84224abfc"; hex.EncodeToString(withUID.Incarnation()[:]) != want {
		t.Errorf("incarnation digest changed: got %s want %s", hex.EncodeToString(withUID.Incarnation()[:]), want)
	}
}

// TestEmptyClusterIDIsRejected: defaulting clusterID would silently recreate the
// collision the type exists to remove, so it must fail loudly at construction.
func TestEmptyClusterIDIsRejected(t *testing.T) {
	id := baseIdentity()
	id.ClusterID = ""
	if _, err := id.WorkloadID(); !errors.Is(err, ErrEmptyClusterID) {
		t.Fatalf("empty ClusterID must return ErrEmptyClusterID, got %v", err)
	}
	env := EnvelopeV2{Version: v2, Identity: id, UID: goldenUID, ConfigHash: goldenConfigHash(t)}
	if _, err := env.SigningDigest(); !errors.Is(err, ErrEmptyClusterID) {
		t.Fatalf("an envelope with an empty ClusterID must not produce a digest, got %v", err)
	}
}
