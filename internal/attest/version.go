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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
)

// Version identifies which hash protocol produced a config hash.
//
// A verifier recomputes the hash from a live Deployment, so it must know which
// normalizer to run BEFORE it can produce any bytes to compare. The version is
// therefore carried alongside the attestation on-chain, never inferred from the
// shape of the hashed payload. See docs/adr/0001-hash-protocol-v2.md.
type Version uint16

const (
	// VersionUnknown is the zero value, and is what an unset on-chain record
	// reads back as. It is never a valid protocol version.
	VersionUnknown Version = 0

	// V1 hashes a narrow subset of a Deployment: namespace, name, non-generated
	// labels, replicas, selector, pod template labels, and for each normal
	// container its name, image string, env var NAMES and resource
	// requests/limits.
	//
	// V1 is a WEAK surface. It does not cover command, args, initContainers,
	// securityContext, volumes, mounts, envFrom/valueFrom, serviceAccountName
	// or host namespaces, so a materially more privileged workload can produce
	// an identical hash. See README "What fields are excluded and why", and the
	// benign/tampered fixture pair that pins the property.
	V1 Version = 1

	// CurrentVersion is what the operator publishes.
	CurrentVersion = V1
)

// ErrUnknownVersion is returned when asked to work with a protocol version this
// build does not implement.
//
// Callers MUST treat this as fatal for the record in question. Trying each
// known version until one verifies would turn an unknown format into a
// downgrade oracle: anyone able to write on-chain could steer a verifier onto a
// weaker hash surface simply by labelling their record with a version the
// verifier is willing to fall back from.
type ErrUnknownVersion struct{ Version Version }

func (e ErrUnknownVersion) Error() string {
	return fmt.Sprintf("attest: unsupported hash protocol version %d (this build implements v%d)", e.Version, V1)
}

// String renders a version for logs and CLI output.
func (v Version) String() string {
	if v == VersionUnknown {
		return "unknown"
	}
	return fmt.Sprintf("v%d", uint16(v))
}

// Supported reports whether this build implements the version.
func (v Version) Supported() bool { return v == V1 }

// IsWeakSurface reports whether a version's hash surface is known to miss
// security-relevant fields, so output can say so rather than let a bare PASS
// imply more than it means.
func (v Version) IsWeakSurface() bool { return v == V1 }

// ConfigHashForVersion normalizes and hashes a Deployment under a specific
// protocol version. This is the single dispatch point: adding v2 adds a branch
// here, and every caller inherits the version check rather than reimplementing
// it.
func ConfigHashForVersion(v Version, d *appsv1.Deployment) ([32]byte, error) {
	switch v {
	case V1:
		return ConfigHash(Normalize(d))
	default:
		return [32]byte{}, ErrUnknownVersion{Version: v}
	}
}

// signingDomain separates these signatures from any other use of the same key.
// Without it, a 34-byte structure signed elsewhere for an unrelated purpose
// could be reinterpreted as an attestation.
const signingDomain = "proof-of-deploy/attestation\x00"

// SigningDigest is the 32 bytes actually signed: SHA-256 over a domain
// separator, the protocol version, and the config hash.
//
// The version is bound cryptographically rather than only stored on-chain. The
// stored value tells a verifier which normalizer to run; binding it here means
// a record whose version field was altered fails signature verification instead
// of merely being recomputed the wrong way.
//
// NOTE for anyone touching the KMS call: this is already a digest. KMS is
// invoked with MessageType=DIGEST precisely so it does NOT hash again, and the
// verifier passes these same bytes to ecdsa.VerifyASN1. Switching KMS to RAW,
// or hashing once more on either side, silently breaks every signature.
func SigningDigest(v Version, configHash [32]byte) [32]byte {
	buf := make([]byte, 0, len(signingDomain)+2+32)
	buf = append(buf, signingDomain...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(v))
	buf = append(buf, configHash[:]...)
	return sha256.Sum256(buf)
}
