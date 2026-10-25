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

// Package publisher decouples "we observed a converged Deployment" from "we
// signed and recorded it on-chain". The reconcile loop only ever calls
// Enqueue, which is non-blocking, so signing latency and chain/RPC failures can
// never block, slow, or crash a reconcile. Delivery is retried asynchronously
// with exponential backoff. This is the mechanism behind the project's hard
// rule that the operator never interferes with delivery.
package publisher

import "context"

// Signer is the subset of the KMS signer the publisher needs.
type Signer interface {
	PublicKeyDER() []byte
	SignDigest(ctx context.Context, digest [32]byte) ([]byte, error)
}
