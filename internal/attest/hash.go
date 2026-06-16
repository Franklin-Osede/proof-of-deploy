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
	"encoding/hex"
	"encoding/json"
)

// CanonicalJSON returns the deterministic JSON encoding of a normalized
// Deployment. Determinism rests on three guarantees, all of which are enforced
// elsewhere in this package and must be preserved:
//
//  1. Struct field order is fixed by declaration order in types.go.
//  2. encoding/json emits map keys in sorted (lexicographic) order.
//  3. Every slice is explicitly sorted in normalize.go.
//
// We intentionally use Marshal (not MarshalIndent): whitespace is not part of
// the contract and compact output is what we hash.
func CanonicalJSON(nd NormalizedDeployment) ([]byte, error) {
	return json.Marshal(nd)
}

// ConfigHash is the SHA-256 over the canonical JSON. This 32-byte digest is the
// value that AWS KMS signs and that the smart contract stores. It is also the
// value the verify CLI recomputes from a live Deployment.
func ConfigHash(nd NormalizedDeployment) ([32]byte, error) {
	b, err := CanonicalJSON(nd)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// ConfigHashHex is ConfigHash rendered as a lowercase hex string, convenient
// for logs and CLI output.
func ConfigHashHex(nd NormalizedDeployment) (string, error) {
	h, err := ConfigHash(nd)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

// MustHex renders a 32-byte hash as a lowercase hex string. Convenience for
// logs and CLI output where an error path is not useful.
func MustHex(h [32]byte) string {
	return hex.EncodeToString(h[:])
}

// DeploymentID is a stable identifier hash for a namespace/name pair. It is the
// on-chain key under which a Deployment's attestations are recorded. Using a
// hash (rather than raw strings) keeps the on-chain identifier fixed-width and
// avoids leaking arbitrary namespace/name strings on a public testnet.
func DeploymentID(namespace, name string) [32]byte {
	return sha256.Sum256([]byte(namespace + "/" + name))
}
