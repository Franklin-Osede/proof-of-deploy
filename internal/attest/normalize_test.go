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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func i32(v int32) *int32 { return &v }

// baseline returns a representative Deployment used across the determinism
// tests. Helpers below mutate copies of it to assert which changes do and do
// not affect the config hash.
func baseline() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments",
			Name:      "api",
			Labels:    map[string]string{"app": "api", "team": "payments"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: i32(3),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "api"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "api"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "server",
							Image: "ghcr.io/acme/api:1.4.2",
							Env: []corev1.EnvVar{
								{Name: "LOG_LEVEL", Value: "info"},
								{Name: "DB_PASSWORD", Value: "super-secret"},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("250m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("1Gi"),
								},
							},
						},
						{
							Name:  "sidecar",
							Image: "ghcr.io/acme/proxy:0.9.0",
						},
					},
				},
			},
		},
	}
}

func mustHash(t *testing.T, d *appsv1.Deployment) [32]byte {
	t.Helper()
	h, err := ConfigHash(Normalize(d))
	if err != nil {
		t.Fatalf("ConfigHash: %v", err)
	}
	return h
}

// TestStableAcrossRuns asserts the hash does not change run to run for the same
// input (guards against map-iteration non-determinism leaking through).
func TestStableAcrossRuns(t *testing.T) {
	want := mustHash(t, baseline())
	for i := 0; i < 100; i++ {
		if got := mustHash(t, baseline()); got != want {
			t.Fatalf("hash unstable across runs at iteration %d", i)
		}
	}
}

// TestContainerOrderIrrelevant asserts that serialized container ordering does
// not change the hash (containers are sorted by name in Normalize).
func TestContainerOrderIrrelevant(t *testing.T) {
	want := mustHash(t, baseline())

	swapped := baseline()
	cs := swapped.Spec.Template.Spec.Containers
	cs[0], cs[1] = cs[1], cs[0]
	if got := mustHash(t, swapped); got != want {
		t.Fatal("hash changed when container order changed; ordering should be normalized away")
	}
}

// TestExcludedFieldsDoNotAffectHash asserts that noisy / non-deterministic
// fields are not part of the attested surface.
func TestExcludedFieldsDoNotAffectHash(t *testing.T) {
	want := mustHash(t, baseline())

	d := baseline()
	// Object metadata noise.
	d.ResourceVersion = "99999"
	d.UID = "1d1e2f3a-0000-0000-0000-000000000000"
	d.Generation = 7
	d.CreationTimestamp = metav1.Now()
	d.Annotations = map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": "{...}",
		"deployment.kubernetes.io/revision":                "4",
	}
	// Generated labels that controllers attach.
	d.Labels["pod-template-hash"] = "abc123"
	d.Spec.Template.Labels["pod-template-hash"] = "abc123"
	// Status is observed output, never attested input.
	d.Status = appsv1.DeploymentStatus{
		ObservedGeneration: 7,
		Replicas:           3,
		AvailableReplicas:  3,
	}

	if got := mustHash(t, d); got != want {
		t.Fatal("excluded field changed the hash; normalization is leaking noisy fields")
	}
}

// TestEnvValuesExcludedNamesIncluded asserts secrets in env VALUES never affect
// the hash, while a changed env NAME does (names are part of declared intent).
func TestEnvValuesExcludedNamesIncluded(t *testing.T) {
	want := mustHash(t, baseline())

	// Changing only an env value must not change the hash.
	valueChanged := baseline()
	valueChanged.Spec.Template.Spec.Containers[0].Env[1].Value = "a-different-secret"
	if got := mustHash(t, valueChanged); got != want {
		t.Fatal("env VALUE affected the hash; values must be excluded")
	}

	// Changing an env name must change the hash.
	nameChanged := baseline()
	nameChanged.Spec.Template.Spec.Containers[0].Env[1].Name = "DB_PASS"
	if got := mustHash(t, nameChanged); got == want {
		t.Fatal("env NAME did not affect the hash; names must be included")
	}
}

// TestReplicasDefaulting asserts an omitted replicas field hashes the same as
// an explicit replicas: 1.
func TestReplicasDefaulting(t *testing.T) {
	explicit := baseline()
	explicit.Spec.Replicas = i32(1)

	omitted := baseline()
	omitted.Spec.Replicas = nil

	if mustHash(t, explicit) != mustHash(t, omitted) {
		t.Fatal("nil replicas did not default to 1 for hashing")
	}
}

// TestImageChangeChangesHash is the core positive case: a new image (the thing
// an attestation most needs to detect) must change the hash.
func TestImageChangeChangesHash(t *testing.T) {
	want := mustHash(t, baseline())

	d := baseline()
	d.Spec.Template.Spec.Containers[0].Image = "ghcr.io/acme/api:1.4.3"
	if got := mustHash(t, d); got == want {
		t.Fatal("image change did not change the hash")
	}
}
