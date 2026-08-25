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
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/franklin1014/proof-of-deploy/internal/publisher"
)

// fakeEnqueuer records every Job the reconciler hands to the publisher, so a
// test can assert exactly how many attestations were requested and for what.
type fakeEnqueuer struct{ jobs []publisher.Job }

func (f *fakeEnqueuer) Enqueue(job publisher.Job) { f.jobs = append(f.jobs, job) }

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("build scheme: %v", err)
	}
	return s
}

// convergedDeployment returns a Deployment whose status satisfies
// rolloutConverged: generation observed, and every replica counter equal to
// the desired count.
func convergedDeployment(namespace, name, image string) *appsv1.Deployment {
	const replicas int32 = 2
	r := replicas
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  namespace,
			Name:       name,
			Generation: 1,
			Labels:     map[string]string{"app": name},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &r,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "server", Image: image}},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			Replicas:           replicas,
			UpdatedReplicas:    replicas,
			ReadyReplicas:      replicas,
			AvailableReplicas:  replicas,
		},
	}
}

func requestFor(d *appsv1.Deployment) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: d.Namespace, Name: d.Name}}
}

func newReconciler(t *testing.T, c client.Client) (*DeploymentReconciler, *fakeEnqueuer) {
	t.Helper()
	enq := &fakeEnqueuer{}
	r := &DeploymentReconciler{Client: c, Scheme: testScheme(t), Publisher: enq}
	r.lastAttested = make(map[[32]byte][32]byte)
	return r, enq
}

func mustReconcile(t *testing.T, r *DeploymentReconciler, req ctrl.Request) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
}

// TestConvergedDeploymentEnqueuedOnce asserts the happy path and the dedup: a
// converged Deployment is attested, and re-reconciling the identical state
// does not enqueue a second attestation (which would cost extra gas).
func TestConvergedDeploymentEnqueuedOnce(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 1 {
		t.Fatalf("first reconcile: got %d enqueued jobs, want 1", len(enq.jobs))
	}

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 1 {
		t.Fatalf("second reconcile of identical state: got %d jobs, want 1 (dedup failed)", len(enq.jobs))
	}
}

// TestNotConvergedIsNotEnqueued asserts a rollout in progress is never
// attested: transient states are not the applied state.
func TestNotConvergedIsNotEnqueued(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2")
	dep.Status.ReadyReplicas = 1 // still rolling out
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 0 {
		t.Fatalf("got %d enqueued jobs for an unconverged rollout, want 0", len(enq.jobs))
	}
}

// TestDeleteThenRecreateIsAttestedAgain is the regression test for the dedup
// cache outliving the object it describes.
//
// A Deployment is attested, deleted, then recreated with byte-identical spec.
// The recreation is a NEW incarnation: it has its own UID and its own lifetime,
// and the on-chain record left by the previous incarnation says nothing about
// it. Because DeploymentID is SHA-256("namespace/name") and carries no UID,
// leaving stale dedup state in place means the new incarnation is silently
// covered by the OLD attestation's timestamp.
//
// Before the fix this test failed at the final assertion: the reconciler
// retained lastAttested across the delete and skipped the recreation, despite
// the comment on the NotFound branch promising the opposite.
func TestDeleteThenRecreateIsAttestedAgain(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)
	req := requestFor(dep)

	// 1. Observed and attested.
	mustReconcile(t, r, req)
	if len(enq.jobs) != 1 {
		t.Fatalf("initial reconcile: got %d jobs, want 1", len(enq.jobs))
	}
	firstJob := enq.jobs[0]

	// 2. Deleted. Reconcile sees NotFound and must not attest anything.
	if err := c.Delete(context.Background(), dep); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mustReconcile(t, r, req)
	if len(enq.jobs) != 1 {
		t.Fatalf("reconcile after delete: got %d jobs, want 1 (a deletion is not attestable)", len(enq.jobs))
	}

	// 3. Recreated with an identical spec — a new incarnation of the same
	//    namespace/name, hashing to the same config hash.
	recreated := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2")
	if err := c.Create(context.Background(), recreated); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	mustReconcile(t, r, req)

	if len(enq.jobs) != 2 {
		t.Fatalf("reconcile after recreate: got %d jobs, want 2; "+
			"the new incarnation was skipped by stale dedup state and is now "+
			"covered only by the previous incarnation's attestation", len(enq.jobs))
	}
	if enq.jobs[1].ConfigHash != firstJob.ConfigHash {
		t.Fatal("recreated Deployment hashed differently; the test no longer exercises the identical-spec case")
	}
	if enq.jobs[1].DeploymentID != firstJob.DeploymentID {
		t.Fatal("recreated Deployment produced a different DeploymentID; expected namespace/name identity")
	}
}

// TestGetErrorIsPropagated asserts that a real read failure (as opposed to
// NotFound) is returned so controller-runtime retries it. Dropping it would
// silently stop attesting a Deployment that still exists.
func TestGetErrorIsPropagated(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2")
	boom := apierrors.NewInternalError(errors.New("apiserver unavailable"))
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(dep).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return boom
			},
		}).
		Build()
	r, enq := newReconciler(t, c)

	_, err := r.Reconcile(context.Background(), requestFor(dep))
	if err == nil {
		t.Fatal("Reconcile swallowed a non-NotFound read error; it must be returned so it is retried")
	}
	if len(enq.jobs) != 0 {
		t.Fatalf("got %d enqueued jobs despite a failed read, want 0", len(enq.jobs))
	}
}
