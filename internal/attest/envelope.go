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
	"crypto/sha256"
	"encoding/binary"
)

// EnvelopeV2 is everything a v2 attestation binds cryptographically.
//
// The rule it enforces: anything a verifier must not be able to swap
// independently of the signature goes in here. In particular the incarnation.
// Storing a UID on-chain without signing it is worth nothing -- a compromised
// publisher EOA could pair a valid KMS signature with a different UID, which
// defeats the whole separation between the account that writes and the KMS key
// that attests.
type EnvelopeV2 struct {
	// Version is the hash protocol that produced ConfigHash.
	Version Version

	// Identity says WHICH workload, across clusters.
	Identity WorkloadIdentityV2

	// UID is the Kubernetes UID of the specific object observed: WHICH
	// INSTANCE. It is deliberately outside ConfigHash, because it describes
	// incarnation rather than configuration -- including it would make an
	// identical redeploy hash differently, and would make manifests
	// unverifiable from Git where no UID exists.
	//
	// Empty means no incarnation is bound. The operator always observes a live
	// object and so always sets it; the empty case belongs to a verifier
	// checking a manifest, which must report a weaker result rather than a
	// plain PASS.
	UID string

	// ConfigHash is the v2 hash surface. See docs/adr/0001-hash-protocol-v2.md.
	ConfigHash [32]byte
}

// envelopeDomain separates these signatures from any other use of the same key,
// and from v1 signatures, which are taken over a different structure entirely.
const envelopeDomain = "proof-of-deploy/attestation/v2\x00"

// incarnationDomain separates incarnation digests from every other digest here.
const incarnationDomain = "proof-of-deploy/incarnation/v2\x00"

// Incarnation is the fixed-width form of the UID, suitable for a Solidity
// bytes32.
//
// A digest rather than the raw UID because the Kubernetes API types a UID as an
// opaque string: it is a UUID in every implementation anyone runs, but nothing
// in the API guarantees a width or a format, and a fixed-width on-chain field
// must not depend on that.
//
// The all-zero value means "no incarnation bound" and is returned only for an
// empty UID, so a zero on-chain field is unambiguous.
func (e EnvelopeV2) Incarnation() [32]byte {
	if e.UID == "" {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte(incarnationDomain), e.UID...))
}

// SigningPreimage returns the exact bytes hashed to produce the signing digest.
//
// Exposed so golden vectors can pin the encoding itself, not merely its digest.
// A change here that happened to collide would otherwise be invisible.
//
// Layout, all lengths big-endian:
//
//	domain                      (fixed, NUL-terminated)
//	uint16  protocol version
//	uint32  length of identity encoding, then that encoding
//	uint32  length of UID, then the UID
//	32      raw config hash bytes
//
// Every variable-length component is length-prefixed, so distinct envelopes
// cannot share a preimage. The trailing config hash is fixed width, so it needs
// no prefix.
func (e EnvelopeV2) SigningPreimage() ([]byte, error) {
	idEnc, err := e.Identity.Encode()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, len(envelopeDomain)+2+4+len(idEnc)+4+len(e.UID)+32)
	buf = append(buf, envelopeDomain...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(e.Version))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(idEnc)))
	buf = append(buf, idEnc...)
	buf = appendLengthPrefixed(buf, e.UID)
	buf = append(buf, e.ConfigHash[:]...)
	return buf, nil
}

// SigningDigest is the 32 bytes actually signed.
//
// NOTE for anyone touching the KMS call: this is already a digest. KMS is
// invoked with MessageType=DIGEST precisely so it does NOT hash again, and the
// verifier passes these same bytes to ecdsa.VerifyASN1. Switching KMS to RAW,
// or hashing once more on either side, silently breaks every signature.
func (e EnvelopeV2) SigningDigest() ([32]byte, error) {
	pre, err := e.SigningPreimage()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(pre), nil
}
