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

package controller

import (
	"context"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/franklin1014/proof-of-deploy/internal/attest"
	"github.com/franklin1014/proof-of-deploy/internal/publisher"
)

// AttestationEnqueuer is the publisher seam. The reconciler only ever enqueues;
// it never waits for signing or chain I/O.
type AttestationEnqueuer interface {
	Enqueue(job publisher.Job)
}

// DeploymentReconciler observes apps/v1 Deployments and, when a rollout has
// converged to a stable applied state, enqueues an attestation of the
// normalized configuration. It has only read RBAC on Deployments and never
// mutates them: the operator is a passive observer and cannot block, delay, or
// alter a deployment.
type DeploymentReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Publisher AttestationEnqueuer

	// lastAttested deduplicates by remembering the most recently attested
	// config hash per Deployment ID. It is an in-memory optimization: on
	// operator restart it is empty, so the next converged observation may
	// re-publish one identical attestation, costing one extra testnet
	// transaction.
	//
	// Entries are dropped when a Deployment is observed to be gone, so a later
	// recreation under the same namespace/name is attested as the new
	// incarnation it is instead of being masked by the previous one's record.
	// See README "Failure modes" for the window this still leaves open.
	mu           sync.Mutex
	lastAttested map[[32]byte][32]byte
}

//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch

// Reconcile observes a Deployment and, on convergence, enqueues an attestation.
// It is idempotent and deliberately tolerant: attestation-side errors (hashing,
// and downstream of here signing and publishing) are logged and swallowed
// rather than retried aggressively, because nothing this controller does should
// ever back-pressure the cluster's handling of the Deployment itself.
//
// The one error that IS returned is a failed read of the Deployment, which
// controller-runtime then retries. Retrying a read applies no back-pressure —
// this controller holds only get/list/watch and cannot mutate, delay, or block
// a Deployment — while swallowing it would silently stop attesting an object
// that still exists.
func (r *DeploymentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	id := attest.DeploymentID(req.Namespace, req.Name)

	var dep appsv1.Deployment
	if err := r.Get(ctx, req.NamespacedName, &dep); err != nil {
		if apierrors.IsNotFound(err) {
			// Deleted. Nothing to attest — the contract has no tombstone — but
			// the dedup entry must go. DeploymentID is SHA-256("namespace/name")
			// and carries no UID, so a recreation reuses this exact key; keeping
			// the entry would make us skip the new incarnation and leave it
			// covered only by the previous incarnation's on-chain record.
			r.forgetAttested(id)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to read deployment; will retry")
		return ctrl.Result{}, err
	}

	if !rolloutConverged(&dep) {
		// Still rolling out (scaling, terminating old pods, generation not yet
		// observed). Wait for a stable state; the watch will re-trigger us as
		// status advances. Attesting here would produce redundant, gas-wasting
		// attestations of transient states.
		return ctrl.Result{}, nil
	}

	nd := attest.Normalize(&dep)
	configHash, err := attest.ConfigHash(nd)
	if err != nil {
		// Hashing a struct we control should not fail; if it ever does, log and
		// move on rather than wedging the reconcile loop.
		log.Error(err, "failed to compute config hash; skipping attestation")
		return ctrl.Result{}, nil
	}

	if r.alreadyAttested(id, configHash) {
		return ctrl.Result{}, nil
	}

	// Optimistically record before enqueue so a burst of identical reconciles
	// does not enqueue duplicates. The work queue also coalesces identical
	// Jobs, and the publisher retries until success, so this is safe.
	r.recordAttested(id, configHash)
	r.Publisher.Enqueue(publisher.Job{
		DeploymentID:   id,
		ConfigHash:     configHash,
		NamespacedName: req.NamespacedName.String(),
	})
	log.Info("enqueued attestation for converged deployment",
		"deployment", req.NamespacedName.String(),
		"configHash", attest.MustHex(configHash),
	)
	return ctrl.Result{}, nil
}

func (r *DeploymentReconciler) alreadyAttested(id, hash [32]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, ok := r.lastAttested[id]
	return ok && prev == hash
}

func (r *DeploymentReconciler) recordAttested(id, hash [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastAttested[id] = hash
}

// forgetAttested drops the dedup entry for a Deployment that no longer exists,
// so a recreation under the same namespace/name is attested afresh.
func (r *DeploymentReconciler) forgetAttested(id [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.lastAttested, id)
}

// rolloutConverged reports whether a Deployment has reached a stable applied
// state worth attesting: the controller has observed the latest spec
// (observedGeneration caught up to generation) AND the rollout is complete with
// no surge or leftover old pods (updated == ready == available == total ==
// desired).
func rolloutConverged(d *appsv1.Deployment) bool {
	if d.Status.ObservedGeneration < d.Generation {
		return false
	}
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	s := d.Status
	return s.UpdatedReplicas == desired &&
		s.ReadyReplicas == desired &&
		s.AvailableReplicas == desired &&
		s.Replicas == desired
}

// SetupWithManager wires the reconciler to watch Deployments. We do NOT filter
// on generation changes: convergence is detected through status updates, which
// do not bump generation, so we must see status events too. Reconcile is cheap
// and idempotent, so the extra wakeups are immaterial.
func (r *DeploymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.lastAttested == nil {
		r.lastAttested = make(map[[32]byte][32]byte)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Deployment{}).
		Named("deployment-attestor").
		Complete(r)
}
