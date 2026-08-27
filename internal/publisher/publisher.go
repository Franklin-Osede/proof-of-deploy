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

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
)

// Signer is the subset of the KMS signer the publisher needs.
type Signer interface {
	PublicKeyDER() []byte
	SignDigest(ctx context.Context, digest [32]byte) ([]byte, error)
}

// ChainWriter is the subset of the chain client the publisher needs.
type ChainWriter interface {
	PublishAttestation(ctx context.Context, deploymentID [32]byte, hashVersion uint16, configHash [32]byte, signature []byte, fingerprint [32]byte) (string, error)
}

// Job is the unit of work enqueued by the reconciler. All fields are comparable
// so the work queue naturally coalesces duplicate enqueues of the same state.
type Job struct {
	DeploymentID [32]byte
	// Version is the hash protocol that produced ConfigHash. It is carried on
	// the job rather than read from a global so that a queued job keeps the
	// version it was built under, even across a protocol upgrade.
	Version        attest.Version
	ConfigHash     [32]byte
	NamespacedName string // for logs only; not hashed or published
}

// Publisher signs and publishes attestations off the reconcile path.
type Publisher struct {
	queue  workqueue.RateLimitingInterface
	signer Signer
	chain  ChainWriter
	log    logr.Logger
}

// New builds a Publisher with an exponential-backoff retry queue (1s base,
// capped at 5m). It does not start any goroutine; register it with the manager
// via Start (it implements manager.Runnable).
func New(signer Signer, chain ChainWriter, log logr.Logger) *Publisher {
	return &Publisher{
		queue: workqueue.NewRateLimitingQueue(
			workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, 5*time.Minute),
		),
		signer: signer,
		chain:  chain,
		log:    log.WithName("publisher"),
	}
}

// Enqueue schedules a Job for asynchronous publication. It never blocks and is
// safe to call from the reconcile loop.
func (p *Publisher) Enqueue(job Job) {
	p.queue.Add(job)
}

// Start runs the publish worker until ctx is cancelled. Implements
// sigs.k8s.io/controller-runtime/pkg/manager.Runnable.
func (p *Publisher) Start(ctx context.Context) error {
	p.log.Info("attestation publisher started")
	go func() {
		<-ctx.Done()
		p.queue.ShutDown()
	}()
	for p.processNext(ctx) {
	}
	p.log.Info("attestation publisher stopped")
	return nil
}

// NeedLeaderElection ensures only the elected leader publishes, avoiding
// duplicate on-chain writes (and duplicate gas) when running multiple replicas.
func (p *Publisher) NeedLeaderElection() bool { return true }

func (p *Publisher) processNext(ctx context.Context) bool {
	item, shutdown := p.queue.Get()
	if shutdown {
		return false
	}
	defer p.queue.Done(item)

	job := item.(Job)
	if err := p.process(ctx, job); err != nil {
		// Never fatal: log, back off, and retry. The reconcile loop is
		// entirely unaffected by repeated publish failures.
		p.log.Error(err, "publish failed; will retry with backoff",
			"deployment", job.NamespacedName,
			"requeues", p.queue.NumRequeues(item),
		)
		p.queue.AddRateLimited(item)
		return true
	}
	p.queue.Forget(item)
	return true
}

func (p *Publisher) process(ctx context.Context, job Job) error {
	// Sign the version-bound digest, not the bare config hash, so a record
	// whose on-chain version field is altered fails verification rather than
	// being recomputed under the wrong normalizer.
	sig, err := p.signer.SignDigest(ctx, attest.SigningDigest(job.Version, job.ConfigHash))
	if err != nil {
		return err
	}
	fingerprint := attest.PublicKeyFingerprintBytes(p.signer.PublicKeyDER())

	txHash, err := p.chain.PublishAttestation(ctx, job.DeploymentID, uint16(job.Version), job.ConfigHash, sig, fingerprint)
	if err != nil {
		return err
	}
	p.log.Info("attestation published",
		"deployment", job.NamespacedName,
		"hashVersion", job.Version.String(),
		"tx", txHash,
	)
	return nil
}
