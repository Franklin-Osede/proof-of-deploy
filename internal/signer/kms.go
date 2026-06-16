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
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsAPI is the narrow slice of the KMS client we use, declared as an interface
// so the publisher can be unit-tested with a fake.
type kmsAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSSigner signs 32-byte digests with a KMS asymmetric key (spec
// ECC_NIST_P256, signing algorithm ECDSA_SHA_256). The public key is fetched
// once at construction and cached; it is published with every attestation and
// used by the verifier.
type KMSSigner struct {
	client kmsAPI
	keyID  string
	pubDER []byte
}

// NewKMSSigner loads AWS configuration from the ambient environment (IRSA,
// instance profile, shared config — never an embedded secret) and fetches the
// public key for keyID. keyID may be a key ID, ARN, or alias.
func NewKMSSigner(ctx context.Context, keyID string) (*KMSSigner, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("signer: load AWS config: %w", err)
	}
	return newWithClient(ctx, kms.NewFromConfig(cfg), keyID)
}

func newWithClient(ctx context.Context, client kmsAPI, keyID string) (*KMSSigner, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("signer: get public key for %q: %w", keyID, err)
	}
	if out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("signer: key %q is not a SIGN_VERIFY key", keyID)
	}
	return &KMSSigner{client: client, keyID: keyID, pubDER: out.PublicKey}, nil
}

// PublicKeyDER returns the cached DER SubjectPublicKeyInfo as returned by KMS.
func (s *KMSSigner) PublicKeyDER() []byte {
	return s.pubDER
}

// KeyID returns the KMS key identifier this signer was constructed with.
func (s *KMSSigner) KeyID() string {
	return s.keyID
}

// SignDigest signs a 32-byte SHA-256 digest. MessageType=DIGEST tells KMS the
// input is already a digest and must not be re-hashed, which matches how the
// verifier checks the signature (over the config hash bytes directly).
func (s *KMSSigner) SignDigest(ctx context.Context, digest [32]byte) ([]byte, error) {
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: KMS sign: %w", err)
	}
	return out.Signature, nil
}
