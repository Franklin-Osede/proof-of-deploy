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

	// What is signed is the version-bound digest, not the bare config hash.
	digest := attestSigningDigest(t, "01-baseline")

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
		t.Fatal("golden signature no longer verifies over the baseline signing digest; " +
			"either the hash surface changed, the version binding changed, or the " +
			"signature is no longer taken over the digest bytes directly")
	}

	// The signature must NOT verify over the bare config hash. If it did, the
	// version binding would be decorative and a relabelled record would still
	// verify.
	if VerifyConfigHashSignature(pub, fixtureHash(t, "01-baseline"), sig) {
		t.Fatal("signature verifies over the bare config hash; the version is not actually bound")
	}

	// Nor under a different protocol version.
	if VerifyConfigHashSignature(pub, SigningDigest(V1+1, fixtureHash(t, "01-baseline")), sig) {
		t.Fatal("signature verifies under a different protocol version")
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

// attestSigningDigest is the digest actually signed for a fixture: the config
// hash bound to the current protocol version.
func attestSigningDigest(t *testing.T, name string) [32]byte {
	t.Helper()
	return SigningDigest(CurrentVersion, fixtureHash(t, name))
}

// TestVersionDispatch pins that an unimplemented version is a hard error rather
// than something a caller can fall back from.
func TestVersionDispatch(t *testing.T) {
	dep := loadFixture(t, "01-baseline")

	got, err := ConfigHashForVersion(V1, dep)
	if err != nil {
		t.Fatalf("v1 dispatch failed: %v", err)
	}
	if want := fixtureHash(t, "01-baseline"); got != want {
		t.Error("ConfigHashForVersion(V1) disagrees with the v1 golden hash")
	}

	for _, v := range []Version{VersionUnknown, 2, 65535} {
		if _, err := ConfigHashForVersion(v, dep); err == nil {
			t.Errorf("ConfigHashForVersion(%d) succeeded; unknown versions must be refused", v)
		} else if _, ok := err.(ErrUnknownVersion); !ok {
			t.Errorf("ConfigHashForVersion(%d) returned %T, want ErrUnknownVersion", v, err)
		}
		if Version(v).Supported() {
			t.Errorf("version %d reports as supported", v)
		}
	}

	if !V1.Supported() {
		t.Error("V1 reports as unsupported")
	}
	if !V1.IsWeakSurface() {
		t.Error("V1 must be flagged as a weak surface so output can say so")
	}
	if VersionUnknown.String() != "unknown" || V1.String() != "v1" {
		t.Errorf("version rendering changed: %q, %q", VersionUnknown, V1)
	}
}

// TestSigningDigestBinding pins that the signed bytes are domain-separated and
// version-bound, so a signature cannot be replayed across versions or confused
// with some other use of the same key.
func TestSigningDigestBinding(t *testing.T) {
	h := fixtureHash(t, "01-baseline")
	other := fixtureHash(t, "02-minimal-defaults")

	if SigningDigest(V1, h) == h {
		t.Error("signing digest equals the raw config hash; there is no binding")
	}
	if SigningDigest(V1, h) == SigningDigest(V1+1, h) {
		t.Error("same digest across protocol versions; the version is not bound")
	}
	if SigningDigest(V1, h) == SigningDigest(V1, other) {
		t.Error("same digest for different config hashes")
	}
	if SigningDigest(V1, h) != SigningDigest(V1, h) {
		t.Error("signing digest is not deterministic")
	}
}

// --- determinism ------------------------------------------------------------
//
// Both properties below were defects found while writing the golden fixtures,
// and were briefly pinned as such. They are now fixed, and these tests assert
// the corrected behaviour: equal inputs must produce equal hashes, whatever
// notation or declaration order the manifest happened to use.
//
// The failure they guard against is the mirror image of the v1 surface
// weakness. That one yields a false PASS; these yield a false FAIL, where
// verification breaks on a change that means nothing operationally.

// TestQuantityCanonicalizationIsByValue asserts that resource quantities are
// hashed by value rather than by the notation they were written in.
//
// resource.Quantity.String() is format-preserving and caches the parsed text,
// so it renders "1Gi", "1024Mi" and "1048576Ki" alike but leaves the identical
// number of bytes written as "1073741824" untouched. canonicalQuantity takes
// the exact decimal and strips trailing zeros instead, giving one string per
// value.
func TestQuantityCanonicalizationIsByValue(t *testing.T) {
	hashFor := func(mem string) [32]byte {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "x"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c", Image: "i", Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(mem)},
				}}},
			}}},
		}
		h, err := ConfigHash(Normalize(d))
		if err != nil {
			t.Fatalf("ConfigHash(%s): %v", mem, err)
		}
		return h
	}

	equivalent := [][]string{
		{"1Gi", "1024Mi", "1048576Ki", "1073741824"},
		{"2G", "2000M", "2000000000"},
		{"1.5Gi", "1610612736"},
		{"0", "0m", "0Ki"},
	}
	for _, group := range equivalent {
		// Guard the fixture itself: these must really be the same quantity.
		first := resource.MustParse(group[0])
		want := hashFor(group[0])
		for _, spelling := range group[1:] {
			q := resource.MustParse(spelling)
			if q.Cmp(first) != 0 {
				t.Fatalf("fixture error: %s and %s are not the same quantity", group[0], spelling)
			}
			if got := hashFor(spelling); got != want {
				t.Errorf("%s and %s are the same quantity but hash differently", group[0], spelling)
			}
		}
	}

	// CPU is the case where a value-based encoding is easiest to get wrong:
	// collapsing to whole units would erase millicores entirely.
	cpu := func(v string) string { return canonicalQuantity(resource.MustParse(v)) }
	if cpu("250m") != cpu("0.25") {
		t.Error("250m and 0.25 are the same CPU request but canonicalize differently")
	}
	if cpu("250m") == cpu("0") {
		t.Error("millicores collapsed to zero; the encoding lost sub-unit precision")
	}
	if cpu("1") != cpu("1000m") {
		t.Error("1 and 1000m are the same CPU request but canonicalize differently")
	}
	// Distinct values must stay distinct.
	if cpu("250m") == cpu("251m") {
		t.Error("distinct CPU quantities collapsed to the same string")
	}
	if canonicalQuantity(resource.MustParse("1Gi")) == canonicalQuantity(resource.MustParse("1G")) {
		t.Error("1Gi and 1G are different amounts but canonicalize the same")
	}
}

// TestSelectorRequirementOrderIsDeterministic asserts that matchExpressions
// sort fully, including a tiebreak on values. Without it, two requirements
// sharing a key and operator keep the order they were declared in and the hash
// depends on how the manifest was written.
func TestSelectorRequirementOrderIsDeterministic(t *testing.T) {
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
	in := func(key string, vals ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: key, Operator: metav1.LabelSelectorOpIn, Values: vals}
	}

	// Same key and operator, different values: the case with no tiebreak.
	a, b := in("zone", "aaa"), in("zone", "zzz")
	if hashFor(a, b) != hashFor(b, a) {
		t.Error("declaration order of two same-key same-operator requirements still changes the hash")
	}

	// One value list a prefix of the other: exercises the length fallback.
	short, long := in("zone", "eu"), in("zone", "eu", "eu-west-1")
	if hashFor(short, long) != hashFor(long, short) {
		t.Error("declaration order changes the hash when one value list prefixes the other")
	}

	// Three-way permutations must all agree.
	c := in("zone", "mmm")
	want := hashFor(a, b, c)
	for _, perm := range [][]metav1.LabelSelectorRequirement{
		{a, c, b}, {b, a, c}, {b, c, a}, {c, a, b}, {c, b, a},
	} {
		if hashFor(perm...) != want {
			t.Error("some permutation of equal-key requirements hashes differently")
			break
		}
	}

	// Genuinely different selectors must still differ.
	if hashFor(a, b) == hashFor(a, c) {
		t.Error("different selector values produced the same hash")
	}
}
