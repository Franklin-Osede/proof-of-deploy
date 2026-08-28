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
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The v2 envelope is defined and pinned BEFORE NormalizeV2 exists, on purpose.
// Writing the normalizer first risks discovering late that the contract, KMS
// and CLI each signed a different notion of identity. See
// docs/adr/0001-hash-protocol-v2.md, "Implementation order".

const envelopeFixtureDir = "testdata/_envelope_v2"

func hashFromHex(t *testing.T, seed string) [32]byte {
	t.Helper()
	var h [32]byte
	b, err := hex.DecodeString(seed)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad fixture hash %q", seed)
	}
	copy(h[:], b)
	return h
}

func referenceIdentity() WorkloadIdentityV2 {
	return WorkloadIdentityV2{
		ClusterID:  "prod-eu-west-1",
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Namespace:  "payments",
		Name:       "api",
	}
}

func referenceEnvelope(t *testing.T) EnvelopeV2 {
	t.Helper()
	return EnvelopeV2{
		Version:    V1,
		Identity:   referenceIdentity(),
		UID:        "1d1e2f3a-0000-0000-0000-000000000000",
		ConfigHash: hashFromHex(t, "89ab57526b689c52761431af4bc5451933c1947b74e0db262438ad1881c17a77"),
	}
}

// TestEnvelopeGoldenVectors pins the exact bytes, not just their digest. A
// change that happened to collide would otherwise be invisible.
func TestEnvelopeGoldenVectors(t *testing.T) {
	id := referenceIdentity()
	env := referenceEnvelope(t)

	idEnc, err := id.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	wid, err := id.WorkloadID()
	if err != nil {
		t.Fatalf("WorkloadID: %v", err)
	}
	pre, err := env.SigningPreimage()
	if err != nil {
		t.Fatalf("SigningPreimage: %v", err)
	}
	dig, err := env.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest: %v", err)
	}
	inc := env.Incarnation()

	body := fmt.Sprintf(
		"identityEncoding  %s\nworkloadID        %s\nincarnation       %s\nsigningPreimage   %s\nsigningDigest     %s\n",
		hex.EncodeToString(idEnc), hex.EncodeToString(wid[:]), hex.EncodeToString(inc[:]),
		hex.EncodeToString(pre), hex.EncodeToString(dig[:]))

	path := filepath.Join(envelopeFixtureDir, "reference.txt")
	if *update {
		if err := os.MkdirAll(envelopeFixtureDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Log("updated envelope golden vectors")
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if body != string(want) {
		t.Errorf("v2 envelope encoding changed -- THIS IS A PROTOCOL CHANGE\n got:\n%swant:\n%s", body, want)
	}
}

// TestIdentityEncodingIsInjective is the property the whole identity scheme
// rests on. Each pair below collides under some plausible naive encoding:
// concatenation with a separator, or concatenation without one. Length
// prefixing must keep them distinct.
func TestIdentityEncodingIsInjective(t *testing.T) {
	base := referenceIdentity()
	with := func(mut func(*WorkloadIdentityV2)) WorkloadIdentityV2 {
		c := base
		mut(&c)
		return c
	}

	pairs := []struct {
		why  string
		a, b WorkloadIdentityV2
	}{
		{
			why: "field boundary shifted between ClusterID and APIVersion (collides without a separator)",
			a:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "ab"; w.APIVersion = "c" }),
			b:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "a"; w.APIVersion = "bc" }),
		},
		{
			why: "separator absorbed into a field between ClusterID and APIVersion (collides with a '/' separator)",
			a:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "a/b"; w.APIVersion = "c" }),
			b:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "a"; w.APIVersion = "b/c" }),
		},
		{
			why: "boundary shifted between Namespace and Name -- exactly v1's DeploymentID defect",
			a:   with(func(w *WorkloadIdentityV2) { w.Namespace = "a"; w.Name = "b/c" }),
			b:   with(func(w *WorkloadIdentityV2) { w.Namespace = "a/b"; w.Name = "c" }),
		},
		{
			why: "boundary shifted between Kind and Namespace",
			a:   with(func(w *WorkloadIdentityV2) { w.Kind = "De"; w.Namespace = "ployment" }),
			b:   with(func(w *WorkloadIdentityV2) { w.Kind = "Dep"; w.Namespace = "loyment" }),
		},
		{
			why: "same names in different clusters must not share an on-chain slot",
			a:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "cluster-a" }),
			b:   with(func(w *WorkloadIdentityV2) { w.ClusterID = "cluster-b" }),
		},
	}

	seen := map[string]string{}
	for _, p := range pairs {
		ea, err := p.a.Encode()
		if err != nil {
			t.Fatalf("%s: encode a: %v", p.why, err)
		}
		eb, err := p.b.Encode()
		if err != nil {
			t.Fatalf("%s: encode b: %v", p.why, err)
		}
		if string(ea) == string(eb) {
			t.Errorf("encoding collision: %s", p.why)
		}

		ia, _ := p.a.WorkloadID()
		ib, _ := p.b.WorkloadID()
		if ia == ib {
			t.Errorf("workload ID collision: %s", p.why)
		}
		for _, e := range []struct {
			id  [32]byte
			why string
		}{{ia, p.why}, {ib, p.why}} {
			k := hex.EncodeToString(e.id[:])
			if prev, dup := seen[k]; dup && prev != e.why {
				t.Errorf("workload ID reused across unrelated identities: %q and %q", prev, e.why)
			}
			seen[k] = e.why
		}
	}
}

// TestIdentityValidation pins that a degenerate identity is refused rather than
// silently encoded. An empty ClusterID in particular would recreate the very
// cross-cluster collision this type exists to remove.
func TestIdentityValidation(t *testing.T) {
	base := referenceIdentity()

	empty := base
	empty.ClusterID = ""
	if err := empty.Validate(); !errors.Is(err, ErrEmptyClusterID) {
		t.Errorf("empty ClusterID: got %v, want ErrEmptyClusterID", err)
	}
	if _, err := empty.Encode(); err == nil {
		t.Error("Encode accepted an empty ClusterID")
	}
	if _, err := empty.WorkloadID(); err == nil {
		t.Error("WorkloadID accepted an empty ClusterID")
	}

	for _, field := range []string{"APIVersion", "Kind", "Namespace", "Name"} {
		c := base
		switch field {
		case "APIVersion":
			c.APIVersion = ""
		case "Kind":
			c.Kind = ""
		case "Namespace":
			c.Namespace = ""
		case "Name":
			c.Name = ""
		}
		if err := c.Validate(); !errors.Is(err, ErrEmptyIdentity) {
			t.Errorf("empty %s: got %v, want ErrEmptyIdentity", field, err)
		}
	}

	if err := base.Validate(); err != nil {
		t.Errorf("reference identity rejected: %v", err)
	}
}

// TestEnvelopeBindsEveryField asserts that nothing in the envelope can be
// swapped without changing the signature. Each mutation below is something a
// compromised publisher EOA would otherwise be free to alter while reusing a
// valid KMS signature.
func TestEnvelopeBindsEveryField(t *testing.T) {
	base := referenceEnvelope(t)
	baseDigest, err := base.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest: %v", err)
	}

	mutations := []struct {
		what string
		mut  func(*EnvelopeV2)
	}{
		{"protocol version", func(e *EnvelopeV2) { e.Version = V1 + 1 }},
		{"cluster", func(e *EnvelopeV2) { e.Identity.ClusterID = "somewhere-else" }},
		{"apiVersion", func(e *EnvelopeV2) { e.Identity.APIVersion = "apps/v1beta1" }},
		{"kind", func(e *EnvelopeV2) { e.Identity.Kind = "StatefulSet" }},
		{"namespace", func(e *EnvelopeV2) { e.Identity.Namespace = "other" }},
		{"name", func(e *EnvelopeV2) { e.Identity.Name = "other" }},
		{"incarnation (UID)", func(e *EnvelopeV2) { e.UID = "99999999-0000-0000-0000-000000000000" }},
		{"UID removed entirely", func(e *EnvelopeV2) { e.UID = "" }},
		{"config hash", func(e *EnvelopeV2) { e.ConfigHash[31] ^= 0x01 }},
	}

	for _, m := range mutations {
		c := base
		m.mut(&c)
		got, err := c.SigningDigest()
		if err != nil {
			t.Fatalf("%s: %v", m.what, err)
		}
		if got == baseDigest {
			t.Errorf("changing the %s did not change the signing digest; it is not bound", m.what)
		}
	}

	again, err := base.SigningDigest()
	if err != nil || again != baseDigest {
		t.Error("signing digest is not deterministic")
	}
}

// TestEnvelopeDomainSeparation asserts the v2 envelope cannot be confused with
// v1 signatures, with a bare config hash, or with an identity digest. Without
// separation, bytes signed for one purpose could be replayed as another.
func TestEnvelopeDomainSeparation(t *testing.T) {
	env := referenceEnvelope(t)
	dig, err := env.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest: %v", err)
	}

	if dig == env.ConfigHash {
		t.Error("envelope digest equals the bare config hash")
	}
	if dig == SigningDigest(env.Version, env.ConfigHash) {
		t.Error("v2 envelope digest collides with the v1 signing digest")
	}
	if wid, _ := env.Identity.WorkloadID(); dig == wid {
		t.Error("envelope digest collides with the workload ID")
	}
	if inc := env.Incarnation(); dig == inc {
		t.Error("envelope digest collides with the incarnation digest")
	}
}

// TestIncarnation pins the fixed-width UID form, including the sentinel that
// makes an absent incarnation unambiguous on-chain.
func TestIncarnation(t *testing.T) {
	env := referenceEnvelope(t)

	var zero [32]byte
	noUID := env
	noUID.UID = ""
	if noUID.Incarnation() != zero {
		t.Error("empty UID must produce the all-zero incarnation, so a zero on-chain field is unambiguous")
	}
	if env.Incarnation() == zero {
		t.Error("a real UID produced the zero sentinel")
	}

	other := env
	other.UID = "99999999-0000-0000-0000-000000000000"
	if other.Incarnation() == env.Incarnation() {
		t.Error("different UIDs produced the same incarnation")
	}
	if env.Incarnation() != referenceEnvelope(t).Incarnation() {
		t.Error("incarnation is not deterministic")
	}
}
