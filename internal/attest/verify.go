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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

// ErrNotECDSA is returned when a parsed public key is not an ECDSA key. The MVP
// uses a single KMS asymmetric key with spec ECC_NIST_P256.
var ErrNotECDSA = errors.New("attest: public key is not an ECDSA key")

// ParsePublicKeyDER parses a DER-encoded SubjectPublicKeyInfo (the exact bytes
// returned by AWS KMS GetPublicKey) into an *ecdsa.PublicKey.
func ParsePublicKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrNotECDSA
	}
	return ec, nil
}

// VerifyConfigHashSignature verifies an ASN.1 DER ECDSA signature produced by
// AWS KMS using SigningAlgorithm=ECDSA_SHA_256 with MessageType=DIGEST over the
// 32-byte config hash.
//
// Note on the digest: with MessageType=DIGEST, KMS treats the supplied bytes as
// the already-computed SHA-256 digest and does NOT hash them again. Our config
// hash IS that SHA-256 digest, so the signature is over configHash[:] directly
// and verification uses the same bytes.
func VerifyConfigHashSignature(pub *ecdsa.PublicKey, configHash [32]byte, derSig []byte) bool {
	return ecdsa.VerifyASN1(pub, configHash[:], derSig)
}

// PublicKeyFingerprintBytes is the raw SHA-256 over the DER SubjectPublicKeyInfo.
// It is fixed-width (32 bytes) so it maps cleanly onto a Solidity bytes32 and is
// the form published on-chain.
func PublicKeyFingerprintBytes(der []byte) [32]byte {
	return sha256.Sum256(der)
}

// PublicKeyFingerprint is PublicKeyFingerprintBytes rendered as hex. The
// operator publishes this fingerprint alongside each attestation and the
// verifier recomputes it from the key it fetched, so a verifier can confirm it
// is checking against the same signer the chain recorded. It is NOT a
// substitute for trusting the key out of band.
func PublicKeyFingerprint(der []byte) string {
	h := PublicKeyFingerprintBytes(der)
	return hex.EncodeToString(h[:])
}
