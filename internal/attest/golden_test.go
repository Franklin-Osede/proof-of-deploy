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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// Golden vectors freeze the v1 hash contract.
//
// The canonical JSON, the config hash and the deployment ID in testdata are the
// wire format. A diff in any golden file is a PROTOCOL CHANGE: it invalidates
// every attestation ever published, because a verifier recomputing the hash
// from a live Deployment will no longer match what was signed.
//
// Regenerate deliberately, never reflexively:
//
//	go test ./internal/attest -run TestGolden -update
//
// and treat the resulting diff as the thing under review.

var update = flag.Bool("update", false, "regenerate golden files under testdata")

const (
	fixtureInput     = "deployment.yaml"
	fixtureCanonical = "canonical.json"
	fixtureHashes    = "hashes.txt"
)

func fixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var names []string
	for _, e := range entries {
		// "_"-prefixed directories hold non-Deployment fixtures (the signature
		// vector) and are not hash cases.
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no fixtures found under testdata")
	}
	return names
}

func loadFixture(t *testing.T, name string) *appsv1.Deployment {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name, fixtureInput))
	if err != nil {
		t.Fatalf("%s: read input: %v", name, err)
	}
	var dep appsv1.Deployment
	if err := yaml.UnmarshalStrict(raw, &dep); err != nil {
		t.Fatalf("%s: decode input: %v", name, err)
	}
	return &dep
}

// fixtureHash is the shared helper used by the equivalence tests.
func fixtureHash(t *testing.T, name string) [32]byte {
	t.Helper()
	h, err := ConfigHash(Normalize(loadFixture(t, name)))
	if err != nil {
		t.Fatalf("%s: ConfigHash: %v", name, err)
	}
	return h
}

func TestGoldenVectors(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			dep := loadFixture(t, name)
			nd := Normalize(dep)

			gotJSON, err := CanonicalJSON(nd)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			gotHash, err := ConfigHash(nd)
			if err != nil {
				t.Fatalf("ConfigHash: %v", err)
			}
			gotID := DeploymentID(dep.Namespace, dep.Name)

			// The fixture set is self-checking: a canonical.json and a
			// hashes.txt that disagree would otherwise both look "golden".
			if sha256.Sum256(gotJSON) != gotHash {
				t.Fatal("ConfigHash is not SHA-256 of CanonicalJSON; the hash contract is broken")
			}

			hashesBody := fmt.Sprintf("configHash    %s\ndeploymentID  %s\n",
				hex.EncodeToString(gotHash[:]), hex.EncodeToString(gotID[:]))

			jsonPath := filepath.Join("testdata", name, fixtureCanonical)
			hashPath := filepath.Join("testdata", name, fixtureHashes)

			if *update {
				// canonical.json holds the EXACT bytes that are hashed: no
				// trailing newline, no indentation. Whitespace is not
				// cosmetic here, it is part of the digest.
				if err := os.WriteFile(jsonPath, gotJSON, 0o644); err != nil {
					t.Fatalf("write %s: %v", jsonPath, err)
				}
				if err := os.WriteFile(hashPath, []byte(hashesBody), 0o644); err != nil {
					t.Fatalf("write %s: %v", hashPath, err)
				}
				t.Logf("updated golden files for %s", name)
				return
			}

			wantJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatalf("read golden JSON (run with -update to create): %v", err)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("canonical JSON changed -- THIS IS A PROTOCOL CHANGE\n got: %s\nwant: %s", gotJSON, wantJSON)
			}

			wantHashes, err := os.ReadFile(hashPath)
			if err != nil {
				t.Fatalf("read golden hashes (run with -update to create): %v", err)
			}
			if hashesBody != string(wantHashes) {
				t.Errorf("hashes changed -- THIS IS A PROTOCOL CHANGE\n got:\n%swant:\n%s", hashesBody, wantHashes)
			}
		})
	}
}

// TestDeploymentIDFormat pins the identifier construction independently of any
// fixture, since it is the on-chain mapping key.
func TestDeploymentIDFormat(t *testing.T) {
	got := DeploymentID("payments", "api")
	want := sha256.Sum256([]byte("payments/api"))
	if got != want {
		t.Fatal("DeploymentID is no longer SHA-256(namespace + \"/\" + name)")
	}
	// DeploymentID is NOT injective on arbitrary strings: "a" + "/" + "b/c" and
	// "a/b" + "/" + "c" are the same bytes. It is safe only because Kubernetes
	// namespaces and names are DNS labels and cannot contain "/".
	//
	// That safety therefore rests on an invariant enforced elsewhere, not on
	// the encoding. Pinned here so that any future change which admits richer
	// identifiers (a cluster name, a UID, a v2 identity tuple) has to confront
	// the ambiguity instead of inheriting it.
	if DeploymentID("a", "b/c") != DeploymentID("a/b", "c") {
		t.Fatal("DeploymentID is now injective across the separator; if the " +
			"encoding was made unambiguous on purpose, update this test and " +
			"the identity notes in the README")
	}
}

// equivalenceGroups list fixtures that MUST produce the same config hash.
var equivalenceGroups = []struct {
	why     string
	members []string
}{
	{
		why:     "declaration order of labels, env, containers and resource keys is normalized away",
		members: []string{"01-baseline", "03-declaration-order"},
	},
	{
		why:     "controller-generated labels are denylisted on both the Deployment and the pod template",
		members: []string{"01-baseline", "04-generated-labels"},
	},
	{
		why:     "annotations, status, uid, resourceVersion, generation, timestamps and env VALUES are excluded",
		members: []string{"01-baseline", "05-excluded-metadata"},
	},
}

func TestEquivalenceGroups(t *testing.T) {
	for _, g := range equivalenceGroups {
		t.Run(strings.Join(g.members, "="), func(t *testing.T) {
			want := fixtureHash(t, g.members[0])
			for _, m := range g.members[1:] {
				if got := fixtureHash(t, m); got != want {
					t.Errorf("%s and %s hash differently but must not: %s",
						g.members[0], m, g.why)
				}
			}
		})
	}
}

// TestV1WeaknessIsPinned asserts the property v1 actually has, which is not the
// property anyone wants: a Deployment can be made materially more privileged
// without changing its config hash.
//
// This test is deliberately phrased so that it FAILS when the hash surface is
// widened. That failure is the signal to move it into the v2 test set and
// invert the assertion -- not to delete it.
func TestV1WeaknessIsPinned(t *testing.T) {
	benign := fixtureHash(t, "08-v1-weakness-benign")
	tampered := fixtureHash(t, "09-v1-weakness-tampered")

	if benign != tampered {
		t.Fatalf("the benign and tampered fixtures now hash differently.\n"+
			"If the hash surface was widened on purpose, this is the intended\n"+
			"outcome: bump the protocol version, move this case to the v2 set,\n"+
			"and assert inequality there.\n benign:   %s\n tampered: %s",
			hex.EncodeToString(benign[:]), hex.EncodeToString(tampered[:]))
	}
	t.Log("v1 confirmed blind to: privileged, runAsUser, capabilities, hostPID, " +
		"hostNetwork, hostPath mounts, serviceAccountName, automountServiceAccountToken, " +
		"command, args, envFrom and initContainers")
}

// --- signature vector -------------------------------------------------------

// ECDSA signing is randomized, so a signature cannot be regenerated
// byte-for-byte. Verification is deterministic, so the golden vector is a fixed
// test key plus one precomputed signature that must keep verifying.
//
// This pins the single most breakable part of the signing contract: the
// signature is over the config hash bytes DIRECTLY. KMS is called with
// MessageType=DIGEST so it does not hash again. Switching KMS to RAW, or making
// the verifier hash before VerifyASN1, breaks this test.

const signatureFixtureDir = "testdata/_signature"

func TestSignatureVector(t *testing.T) {
	keyPath := filepath.Join(signatureFixtureDir, "test-key.pem")
	pubPath := filepath.Join(signatureFixtureDir, "public-key.der")
	sigPath := filepath.Join(signatureFixtureDir, "signature.der")
	fpPath := filepath.Join(signatureFixtureDir, "fingerprint.txt")

	digest := fixtureHash(t, "01-baseline")

	if *update {
		regenerateSignatureFixture(t, digest, keyPath, pubPath, sigPath, fpPath)
		return
	}

	pubDER, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key (run with -update to create): %v", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature (run with -update to create): %v", err)
	}
	wantFP, err := os.ReadFile(fpPath)
	if err != nil {
		t.Fatalf("read fingerprint (run with -update to create): %v", err)
	}

	pub, err := ParsePublicKeyDER(pubDER)
	if err != nil {
		t.Fatalf("ParsePublicKeyDER on a KMS-shaped SPKI DER failed: %v", err)
	}
	if pub.Curve.Params().Name != "P-256" {
		t.Fatalf("fixture key is %s, want P-256", pub.Curve.Params().Name)
	}

	if got := PublicKeyFingerprint(pubDER) + "\n"; got != string(wantFP) {
		t.Errorf("fingerprint changed\n got: %swant: %s", got, wantFP)
	}

	if !VerifyConfigHashSignature(pub, digest, sig) {
		t.Fatal("golden signature no longer verifies over the baseline config hash; " +
			"either the hash surface changed or the signature is no longer taken " +
			"over the digest bytes directly")
	}

	// Negative: a single flipped bit in the digest must be rejected.
	tampered := digest
	tampered[0] ^= 0xff
	if VerifyConfigHashSignature(pub, tampered, sig) {
		t.Fatal("signature verified over a tampered digest")
	}

	// Negative: a truncated signature must be rejected, not panic.
	if len(sig) > 8 && VerifyConfigHashSignature(pub, digest, sig[:len(sig)-4]) {
		t.Fatal("signature verified with trailing bytes removed")
	}

	// Negative: a non-ECDSA key must be refused by name, not by panic.
	if _, err := ParsePublicKeyDER([]byte("not a DER SPKI")); err == nil {
		t.Fatal("ParsePublicKeyDER accepted garbage")
	}
}

func regenerateSignatureFixture(t *testing.T, digest [32]byte, keyPath, pubPath, sigPath, fpPath string) {
	t.Helper()
	if err := os.MkdirAll(signatureFixtureDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var priv *ecdsa.PrivateKey
	if raw, err := os.ReadFile(keyPath); err == nil {
		// Reuse the existing test key so the fingerprint stays stable across
		// regenerations; only the signature is re-taken.
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("existing %s is not PEM", keyPath)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse existing test key: %v", err)
		}
		priv = k.(*ecdsa.PrivateKey)
	} else {
		// First run: mint the test key. It is committed so the fingerprint
		// stays stable. TEST ONLY -- it signs nothing outside this package.
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate test key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatalf("marshal test key: %v", err)
		}
		mustWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		priv = k
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	mustWrite(t, pubPath, pubDER)
	mustWrite(t, sigPath, sig)
	mustWrite(t, fpPath, []byte(PublicKeyFingerprint(pubDER)+"\n"))
	t.Logf("regenerated signature fixture")
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// --- pinned determinism defects ---------------------------------------------
//
// The two tests below assert behaviour that is WRONG. They exist so the defects
// are visible, regression-tested and impossible to fix by accident. Like
// TestV1WeaknessIsPinned, each is written to FAIL once the defect is fixed;
// that failure is the signal to invert the assertion under a new protocol
// version, not to delete the test.

// TestQuantityCanonicalizationIsFormatNotValue pins that the hash follows
// resource.Quantity's FORMAT rather than its VALUE.
//
// 1Gi, 1024Mi and 1048576Ki all canonicalize to "1Gi", but the same number of
// bytes written as the plain integer 1073741824 stays "1073741824" because it
// parses as DecimalSI rather than BinarySI. Two Deployments requesting exactly
// the same memory therefore hash differently.
//
// This is the inverse of the v1 weakness: it produces a false FAIL. Rewriting
// "1Gi" as "1073741824" in a manifest changes nothing operationally and breaks
// verification.
func TestQuantityCanonicalizationIsFormatNotValue(t *testing.T) {
	hashFor := func(mem string) [32]byte {
		q := resource.MustParse(mem)
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "x"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c", Image: "i", Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceMemory: q},
				}}},
			}}},
		}
		h, err := ConfigHash(Normalize(d))
		if err != nil {
			t.Fatalf("ConfigHash(%s): %v", mem, err)
		}
		return h
	}

	// Sanity: all four spellings are the same number of bytes.
	for _, f := range []string{"1Gi", "1024Mi", "1048576Ki", "1073741824"} {
		q := resource.MustParse(f)
		if got := q.Value(); got != 1073741824 {
			t.Fatalf("%s is %d bytes, expected the fixture to use equal values", f, got)
		}
	}

	binary := hashFor("1Gi")
	if hashFor("1024Mi") != binary || hashFor("1048576Ki") != binary {
		t.Error("binary-suffixed spellings no longer agree with each other")
	}
	if hashFor("1073741824") == binary {
		t.Fatal("quantities are now canonicalized by value, not format.\n" +
			"That is the desired behaviour: bump the protocol version and assert\n" +
			"equality here instead of inequality.")
	}
	t.Log("v1 confirmed: equal memory quantities hash differently when spelled as a plain integer")
}

// TestSelectorRequirementOrderIsNotDeterministic pins that normalizeSelector
// sorts matchExpressions by (key, operator) with no tiebreak on values, so two
// requirements sharing a key and operator keep their declaration order and the
// hash depends on how the manifest was written.
func TestSelectorRequirementOrderIsNotDeterministic(t *testing.T) {
	hashFor := func(reqs ...metav1.LabelSelectorRequirement) [32]byte {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "x"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchExpressions: reqs},
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c", Image: "i"}}}},
			},
		}
		h, err := ConfigHash(Normalize(d))
		if err != nil {
			t.Fatalf("ConfigHash: %v", err)
		}
		return h
	}
	a := metav1.LabelSelectorRequirement{Key: "zone", Operator: metav1.LabelSelectorOpIn, Values: []string{"aaa"}}
	b := metav1.LabelSelectorRequirement{Key: "zone", Operator: metav1.LabelSelectorOpIn, Values: []string{"zzz"}}

	if hashFor(a, b) == hashFor(b, a) {
		t.Fatal("matchExpressions now sort deterministically across equal (key, operator).\n" +
			"That is the desired behaviour: bump the protocol version and assert\n" +
			"equality here instead of inequality.")
	}
	t.Log("v1 confirmed: matchExpressions declaration order leaks into the hash when key and operator match")
}
