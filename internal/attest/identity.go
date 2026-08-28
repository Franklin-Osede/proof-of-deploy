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
	"errors"
	"fmt"
)

// WorkloadIdentityV2 names a workload unambiguously across clusters.
//
// v1 identified a workload as SHA-256("namespace/name"), which has two defects
// this type exists to fix:
//
//   - No cluster. "payments/api" in two clusters sharing a registry occupies
//     one on-chain slot, and each overwrites the other.
//   - Ambiguous encoding. "a" + "/" + "b/c" and "a/b" + "/" + "c" are the same
//     bytes; v1 is safe only because Kubernetes names cannot contain "/", which
//     makes the guarantee rest on an invariant enforced somewhere else.
//
// Identity is deliberately separate from incarnation. This type says WHICH
// workload; the UID in the envelope says WHICH INSTANCE of it. See
// docs/adr/0001-hash-protocol-v2.md.
type WorkloadIdentityV2 struct {
	// ClusterID must be explicitly configured and stable for the lifetime of
	// the cluster. It must NOT be derived from the kubeconfig context name,
	// which is local, mutable, and bound to nothing.
	ClusterID string

	APIVersion string // e.g. "apps/v1"
	Kind       string // e.g. "Deployment"
	Namespace  string
	Name       string
}

// Identity field constraints. These are sanity bounds, not Kubernetes
// validation: the point is that a caller cannot silently produce a degenerate
// identity that collides with another one.
var (
	ErrEmptyClusterID = errors.New("attest: ClusterID is required; an empty cluster identity reintroduces the v1 cross-cluster collision")
	ErrEmptyIdentity  = errors.New("attest: identity fields must be non-empty")
)

// maxFieldLen bounds each encoded field. Kubernetes names and namespaces are at
// most 253 characters; this leaves ample room while keeping the uint32 length
// prefix from ever being the interesting failure mode.
const maxFieldLen = 1 << 16

// Validate reports whether the identity is usable. An empty ClusterID is
// rejected specifically: defaulting it would quietly recreate the collision
// this type exists to remove.
func (w WorkloadIdentityV2) Validate() error {
	if w.ClusterID == "" {
		return ErrEmptyClusterID
	}
	for name, v := range map[string]string{
		"APIVersion": w.APIVersion,
		"Kind":       w.Kind,
		"Namespace":  w.Namespace,
		"Name":       w.Name,
	} {
		if v == "" {
			return fmt.Errorf("%w: %s", ErrEmptyIdentity, name)
		}
	}
	for name, v := range map[string]string{
		"ClusterID": w.ClusterID, "APIVersion": w.APIVersion,
		"Kind": w.Kind, "Namespace": w.Namespace, "Name": w.Name,
	} {
		if len(v) > maxFieldLen {
			return fmt.Errorf("attest: %s exceeds %d bytes", name, maxFieldLen)
		}
	}
	return nil
}

// String renders the identity for logs and CLI output. It is NOT the encoding
// used for hashing -- it is lossy on purpose, and must never be fed to a digest.
func (w WorkloadIdentityV2) String() string {
	return fmt.Sprintf("%s/%s %s/%s in cluster %q", w.APIVersion, w.Kind, w.Namespace, w.Name, w.ClusterID)
}

// appendLengthPrefixed writes a 4-byte big-endian length followed by the bytes.
//
// This is what makes the encoding injective. Plain concatenation is not: with
// separators, a field containing the separator forges a different tuple with
// the same bytes; without them, adjacent fields merge. Length prefixing means
// distinct field tuples always produce distinct byte strings, so no two
// identities can share a preimage.
func appendLengthPrefixed(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// identityDomain separates workload identifiers from every other digest this
// project computes, so an identity can never be mistaken for a config hash.
const identityDomain = "proof-of-deploy/workload-identity/v2\x00"

// Encode returns the canonical, injective byte encoding of the identity.
//
// The field ORDER is part of the wire format. Reordering, adding, or removing a
// field changes every workload ID this protocol has ever produced. Golden
// vectors pin it.
func (w WorkloadIdentityV2) Encode() ([]byte, error) {
	if err := w.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(identityDomain)+len(w.ClusterID)+len(w.APIVersion)+
		len(w.Kind)+len(w.Namespace)+len(w.Name)+5*4)
	buf = append(buf, identityDomain...)
	buf = appendLengthPrefixed(buf, w.ClusterID)
	buf = appendLengthPrefixed(buf, w.APIVersion)
	buf = appendLengthPrefixed(buf, w.Kind)
	buf = appendLengthPrefixed(buf, w.Namespace)
	buf = appendLengthPrefixed(buf, w.Name)
	return buf, nil
}

// WorkloadID is the on-chain key: SHA-256 over the canonical identity encoding.
//
// Replaces v1's DeploymentID. Unlike that one it is injective by construction
// rather than by relying on Kubernetes naming rules, and it distinguishes the
// same namespace/name in different clusters.
func (w WorkloadIdentityV2) WorkloadID() ([32]byte, error) {
	enc, err := w.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}
