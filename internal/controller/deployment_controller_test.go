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

	"github.com/franklin1014/proof-of-deploy/internal/attest"
	"github.com/franklin1014/proof-of-deploy/internal/publisher"
)

const testCluster = "test-cluster"

// fakeEnqueuer records every revision the reconciler hands to the publisher,
// so a test can assert exactly what was requested.
type fakeEnqueuer struct{ jobs []publisher.Desired }

func (f *fakeEnqueuer) Enqueue(d publisher.Desired) error {
	f.jobs = append(f.jobs, d)
	return nil
}

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
// the desired count. The UID is set explicitly because the fake client does not
// assign one, and the incarnation is derived from it.
func convergedDeployment(namespace, name, image string, uid types.UID) *appsv1.Deployment {
	const replicas int32 = 2
	r := replicas
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  namespace,
			Name:       name,
			UID:        uid,
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
	r := &DeploymentReconciler{Client: c, Scheme: testScheme(t), Publisher: enq, ClusterID: testCluster}
	return r, enq
}

func mustReconcile(t *testing.T, r *DeploymentReconciler, req ctrl.Request) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
}

// TestConvergedDeploymentIsEnqueuedAsV2 asserts the happy path: a converged
// Deployment is handed to the publisher under its full v2 identity, bound to
// the UID of the object observed.
//
// Re-reconciling identical state enqueues the identical revision again. Not
// publishing it twice is the publisher's job, which it does by comparing with
// what it has confirmed (see TestMinedSuccessConfirmsAndStops).
func TestConvergedDeploymentIsEnqueuedAsV2(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2", "uid-1")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 1 {
		t.Fatalf("first reconcile: got %d enqueued revisions, want 1", len(enq.jobs))
	}
	got := enq.jobs[0]
	wantID := attest.WorkloadIdentityV2{
		ClusterID: testCluster, APIVersion: "apps/v1", Kind: "Deployment",
		Namespace: "payments", Name: "api",
	}
	if got.Identity != wantID {
		t.Errorf("identity %+v, want %+v", got.Identity, wantID)
	}
	if got.UID != "uid-1" {
		t.Errorf("UID %q, want the observed object's", got.UID)
	}
	if got.Version != attest.V2 {
		t.Errorf("version %v, want v2", got.Version)
	}

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 2 || enq.jobs[1] != got {
		t.Fatalf("re-reconcile of identical state must enqueue the identical revision, got %+v", enq.jobs)
	}
}

// TestNotConvergedIsNotEnqueued asserts a rollout in progress is never
// attested: transient states are not the applied state.
func TestNotConvergedIsNotEnqueued(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2", "uid-1")
	dep.Status.ReadyReplicas = 1 // still rolling out
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)

	mustReconcile(t, r, requestFor(dep))
	if len(enq.jobs) != 0 {
		t.Fatalf("got %d enqueued jobs for an unconverged rollout, want 0", len(enq.jobs))
	}
}

// TestDeleteThenRecreateIsAttestedAgain: a Deployment is attested, deleted,
// then recreated with a byte-identical spec.
//
// The recreation is a NEW incarnation with its own lifetime, and the on-chain
// record left by the previous one says nothing about it. v2 carries the UID,
// so the recreation is a distinct revision even though its config hash is the
// same, and the publisher cannot mistake it for the one already confirmed.
func TestDeleteThenRecreateIsAttestedAgain(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2", "uid-1")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(dep).Build()
	r, enq := newReconciler(t, c)
	req := requestFor(dep)

	mustReconcile(t, r, req)
	if len(enq.jobs) != 1 {
		t.Fatalf("initial reconcile: got %d revisions, want 1", len(enq.jobs))
	}
	first := enq.jobs[0]

	if err := c.Delete(context.Background(), dep); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mustReconcile(t, r, req)
	if len(enq.jobs) != 1 {
		t.Fatalf("reconcile after delete: got %d revisions, want 1 (a deletion is not attestable)", len(enq.jobs))
	}

	recreated := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2", "uid-2")
	if err := c.Create(context.Background(), recreated); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	mustReconcile(t, r, req)

	if len(enq.jobs) != 2 {
		t.Fatalf("reconcile after recreate: got %d revisions, want 2", len(enq.jobs))
	}
	second := enq.jobs[1]
	if second.ConfigHash != first.ConfigHash {
		t.Fatal("recreated Deployment hashed differently; the test no longer exercises the identical-spec case")
	}
	if second.UID == first.UID {
		t.Fatal("the recreation carries the previous incarnation's UID")
	}
}

// TestGetErrorIsPropagated asserts that a real read failure (as opposed to
// NotFound) is returned so controller-runtime retries it. Dropping it would
// silently stop attesting a Deployment that still exists.
func TestGetErrorIsPropagated(t *testing.T) {
	dep := convergedDeployment("payments", "api", "ghcr.io/acme/api:1.4.2", "uid-1")
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
