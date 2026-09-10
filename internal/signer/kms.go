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

// Package signer delegates all signing to AWS KMS. The operator never holds,
// reads, or derives raw private key material — the private key never leaves
// KMS. The trust boundary of the whole system is exactly this KMS key plus the
// IAM principal allowed to call Sign on it (see README "Trust boundary").
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
)

// kmsAPI is the narrow slice of the KMS client we use, declared as an interface
// so the constructor and signing path can be exercised with a fake.
type kmsAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSSigner signs 32-byte digests with a KMS asymmetric key.
//
// Everything it requires is checked at construction, so a misconfigured key is
// a startup failure rather than a run of unverifiable attestations.
type KMSSigner struct {
	client kmsAPI
	// keyID is the CANONICAL identifier KMS returned, not the one supplied.
	//
	// Configuration may name an alias. If it does, and the alias is repointed
	// after startup, GetPublicKey has already cached the old key while Sign
	// would reach the new one: the published record would then carry the old
	// fingerprint beside a signature from a different key, and could never
	// verify. Signing by canonical id removes that window.
	keyID string
	// configuredKeyID is what the operator was told to use, kept for logs so a
	// canonical ARN in an error is traceable back to the alias.
	configuredKeyID string
	pubDER          []byte
	pub             *ecdsa.PublicKey
}

// signingAlgorithm is the only algorithm this protocol uses.
const signingAlgorithm = kmstypes.SigningAlgorithmSpecEcdsaSha256

// NewKMSSigner loads AWS configuration from the ambient environment (IRSA,
// instance profile, shared config — never an embedded secret) and resolves
// keyID, which may be a key id, ARN, or alias.
func NewKMSSigner(ctx context.Context, keyID string) (*KMSSigner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("signer: load AWS config: %w", err)
	}
	return newWithClient(ctx, kms.NewFromConfig(cfg), keyID)
}

// newWithClient validates every property the protocol depends on.
//
// A key that is the wrong spec, the wrong usage, or cannot produce the
// algorithm we use will fail here and stop the operator from starting, rather
// than failing on the first attestation with gas already spent.
func newWithClient(ctx context.Context, client kmsAPI, keyID string) (*KMSSigner, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("signer: key id is empty")
	}

	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("signer: get public key for %q: %w", keyID, err)
	}
	if out == nil {
		return nil, fmt.Errorf("signer: KMS returned no response for %q", keyID)
	}

	if out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("signer: key %q has usage %s, want %s",
			keyID, out.KeyUsage, kmstypes.KeyUsageTypeSignVerify)
	}
	if out.KeySpec != kmstypes.KeySpecEccNistP256 {
		// An RSA or other-curve key would fail later, at signing time, with a
		// far less obvious message.
		return nil, fmt.Errorf("signer: key %q has spec %s, want %s",
			keyID, out.KeySpec, kmstypes.KeySpecEccNistP256)
	}
	if !slices.Contains(out.SigningAlgorithms, signingAlgorithm) {
		return nil, fmt.Errorf("signer: key %q does not offer %s (offers %v)",
			keyID, signingAlgorithm, out.SigningAlgorithms)
	}
	if len(out.PublicKey) == 0 {
		return nil, fmt.Errorf("signer: KMS returned an empty public key for %q", keyID)
	}

	// Copy: the response buffer belongs to the caller of GetPublicKey, and a
	// fake or a future SDK could reuse it.
	pubDER := make([]byte, len(out.PublicKey))
	copy(pubDER, out.PublicKey)

	pub, err := attest.ParsePublicKeyDER(pubDER)
	if err != nil {
		return nil, fmt.Errorf("signer: key %q returned an unparseable public key: %w", keyID, err)
	}
	if pub.Curve != elliptic.P256() {
		// KeySpec said P-256; the key material disagreeing means the two do not
		// describe the same thing, and neither can be trusted.
		return nil, fmt.Errorf("signer: key %q reports spec %s but its public key is on curve %s",
			keyID, out.KeySpec, pub.Curve.Params().Name)
	}

	canonical := keyID
	if out.KeyId != nil && *out.KeyId != "" {
		canonical = *out.KeyId
	}

	return &KMSSigner{
		client:          client,
		keyID:           canonical,
		configuredKeyID: keyID,
		pubDER:          pubDER,
		pub:             pub,
	}, nil
}

// PublicKeyDER returns a copy of the DER SubjectPublicKeyInfo as returned by
// KMS. A copy, so a caller mutating the result cannot change what this signer
// believes its own key to be.
func (s *KMSSigner) PublicKeyDER() []byte {
	out := make([]byte, len(s.pubDER))
	copy(out, s.pubDER)
	return out
}

// KeyID returns the canonical identifier KMS resolved, which is what is
// actually signed with. It may differ from the configured value when that was
// an alias.
func (s *KMSSigner) KeyID() string { return s.keyID }

// ConfiguredKeyID returns the identifier the operator supplied.
func (s *KMSSigner) ConfiguredKeyID() string { return s.configuredKeyID }

// SignDigest signs a 32-byte digest.
//
// MessageType=DIGEST tells KMS the input is already a digest and must not be
// re-hashed, which matches how the verifier checks the signature: over these
// same bytes. Under v2 the digest is the ENVELOPE digest -- domain separator,
// protocol version, workload identity, incarnation and config hash -- not the
// config hash on its own.
//
// The response is checked rather than trusted. A signature that does not verify
// locally is refused here, so an inconsistent KMS response, or a
// compatible-looking endpoint that is wrong, becomes an immediate error instead
// of a published record that can never be verified.
func (s *KMSSigner) SignDigest(ctx context.Context, digest [32]byte) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		// The canonical id, never the configured alias.
		KeyId:            &s.keyID,
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: KMS sign: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("signer: KMS returned no response to sign")
	}
	if len(out.Signature) == 0 {
		return nil, fmt.Errorf("signer: KMS returned an empty signature")
	}
	if out.SigningAlgorithm != signingAlgorithm {
		return nil, fmt.Errorf("signer: KMS signed with %s, expected %s",
			out.SigningAlgorithm, signingAlgorithm)
	}
	if out.KeyId != nil && *out.KeyId != s.keyID {
		// The key moved under us -- an alias repointed, or a response for a
		// request we did not make. Either way the signature does not belong to
		// the fingerprint we publish.
		return nil, fmt.Errorf("signer: KMS signed with key %q, expected %q", *out.KeyId, s.keyID)
	}

	sig := make([]byte, len(out.Signature))
	copy(sig, out.Signature)

	if !attest.VerifyConfigHashSignature(s.pub, digest, sig) {
		return nil, fmt.Errorf("signer: KMS returned a signature that does not verify against the cached public key")
	}
	return sig, nil
}
