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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	fixtureCanonicalV2 = "canonical_v2.json"
	fixtureHashesV2    = "hashes_v2.txt"
)

func fixtureHashV2(t *testing.T, name string) [32]byte {
	t.Helper()
	h, err := ConfigHashV2(NormalizeV2(loadFixture(t, name)))
	if err != nil {
		t.Fatalf("%s: ConfigHashV2: %v", name, err)
	}
	return h
}

// TestV2GoldenVectors freezes the v2 wire format the same way v1 is frozen.
func TestV2GoldenVectors(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			nd := NormalizeV2(loadFixture(t, name))
			gotJSON, err := CanonicalJSONV2(nd)
			if err != nil {
				t.Fatalf("CanonicalJSONV2: %v", err)
			}
			gotHash, err := ConfigHashV2(nd)
			if err != nil {
				t.Fatalf("ConfigHashV2: %v", err)
			}
			if sha256.Sum256(gotJSON) != gotHash {
				t.Fatal("ConfigHashV2 is not SHA-256 of CanonicalJSONV2")
			}

			body := fmt.Sprintf("configHash    %s\n", hex.EncodeToString(gotHash[:]))
			jsonPath := filepath.Join("testdata", name, fixtureCanonicalV2)
			hashPath := filepath.Join("testdata", name, fixtureHashesV2)

			if *update {
				if err := os.WriteFile(jsonPath, gotJSON, 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				if err := os.WriteFile(hashPath, []byte(body), 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				return
			}
			wantJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatalf("read golden (run with -update): %v", err)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("v2 canonical JSON changed -- THIS IS A PROTOCOL CHANGE\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
			wantHash, err := os.ReadFile(hashPath)
			if err != nil {
				t.Fatalf("read golden (run with -update): %v", err)
			}
			if body != string(wantHash) {
				t.Errorf("v2 hash changed -- THIS IS A PROTOCOL CHANGE\n got: %swant: %s", body, wantHash)
			}
		})
	}
}

// TestV2DetectsTheTamperedWorkload is the point of the whole protocol change.
//
// Under v1 the benign and tampered fixtures hash identically: a workload can be
// made privileged, run as root, given the host PID namespace and the host root
// filesystem, handed a different ServiceAccount and told to run a different
// program, and still verify as PASS. Under v2 that must be impossible.
func TestV2DetectsTheTamperedWorkload(t *testing.T) {
	benignV1 := fixtureHash(t, "08-v1-weakness-benign")
	tamperedV1 := fixtureHash(t, "09-v1-weakness-tampered")
	if benignV1 != tamperedV1 {
		t.Fatal("the v1 fixtures no longer collide; the pair no longer demonstrates what it is for")
	}

	benignV2 := fixtureHashV2(t, "08-v1-weakness-benign")
	tamperedV2 := fixtureHashV2(t, "09-v1-weakness-tampered")
	if benignV2 == tamperedV2 {
		t.Fatalf("v2 does not distinguish the tampered workload from the benign one.\n"+
			"It differs in: privileged, runAsUser, capabilities, hostPID, hostNetwork,\n"+
			"a hostPath mount, serviceAccountName, automountServiceAccountToken,\n"+
			"command, args, envFrom and an extra init container.\n hash: %s",
			hex.EncodeToString(benignV2[:]))
	}
}

// v2IncludedPodSpecFields and v2ExcludedPodSpecFields must together account for
// EVERY field of the upstream PodSpec. See TestV2SurfaceAccountsForEveryField.
var v2IncludedPodSpecFields = map[string]bool{
	"InitContainers": true, "Containers": true,
	"ServiceAccountName": true, "AutomountServiceAccountToken": true, "ImagePullSecrets": true,
	"HostNetwork": true, "HostPID": true, "HostIPC": true, "HostUsers": true,
	"RuntimeClassName": true, "SecurityContext": true, "ShareProcessNamespace": true,
	"Volumes": true, "ResourceClaims": true,
	"HostAliases": true, "DNSPolicy": true, "DNSConfig": true,
	"Hostname": true, "Subdomain": true, "SetHostnameAsFQDN": true, "EnableServiceLinks": true,
	"NodeSelector": true, "NodeName": true, "SchedulerName": true, "Affinity": true,
	"Tolerations": true, "TopologySpreadConstraints": true,
	"PriorityClassName": true, "PreemptionPolicy": true, "SchedulingGates": true, "OS": true,
}

// Each exclusion carries the reason it survives the inclusion rule: a field is
// attested when it changes the Pod's runtime, credentials, isolation, resource
// access, or placement eligibility.
var v2ExcludedPodSpecFields = map[string]string{
	"EphemeralContainers":           "cannot be set through a Deployment template; the API rejects them there",
	"RestartPolicy":                 "constrained to Always for Deployments, so it carries no information",
	"TerminationGracePeriodSeconds": "shutdown timing, not what the workload can do",
	"ActiveDeadlineSeconds":         "a lifetime bound, not a privilege",
	"DeprecatedServiceAccount":      "legacy mirror of ServiceAccountName, which is attested",
	"Priority":                      "resolved by admission from PriorityClassName, which is attested",
	"ReadinessGates":                "affects readiness reporting, not capability",
	"Overhead":                      "resource accounting derived from RuntimeClassName, which is attested",
}

var v2IncludedContainerFields = map[string]bool{
	"Name": true, "Image": true, "Command": true, "Args": true, "WorkingDir": true,
	"Env": true, "EnvFrom": true, "Ports": true, "ImagePullPolicy": true,
	"Resources": true, "VolumeMounts": true, "VolumeDevices": true, "SecurityContext": true,
	"LivenessProbe": true, "ReadinessProbe": true, "StartupProbe": true, "Lifecycle": true,
	"RestartPolicy": true,
}

var v2ExcludedContainerFields = map[string]string{
	"ResizePolicy":             "governs whether an in-place resource resize restarts the container, not privilege",
	"TerminationMessagePath":   "an output channel for the exit message",
	"TerminationMessagePolicy": "an output channel for the exit message",
	"Stdin":                    "allocates a console; attaching to it requires separate RBAC",
	"StdinOnce":                "allocates a console; attaching to it requires separate RBAC",
	"TTY":                      "allocates a console; attaching to it requires separate RBAC",
}

// TestV2SurfaceAccountsForEveryField is what makes an allowlist defensible.
//
// Without it, a field added upstream is silently absent from the hash: the
// attested surface quietly shrinks relative to what Kubernetes can express, and
// nothing fails. This test forces a decision instead — when the Kubernetes
// libraries gain a field, it must be classified as included or excluded with a
// stated reason, and the classification is argued against the inclusion rule.
//
// It already earned itself: it caught ImagePullSecrets, ShareProcessNamespace,
// HostUsers, ResourceClaims, EnableServiceLinks, SchedulingGates, OS, and the
// container-level RestartPolicy that distinguishes a sidecar from a plain init
// container, all of which had been missed.
func TestV2SurfaceAccountsForEveryField(t *testing.T) {
	check := func(what string, typ reflect.Type, included map[string]bool, excluded map[string]string) {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			_, isExcluded := excluded[name]
			if !included[name] && !isExcluded {
				t.Errorf("%s.%s is in neither the v2 surface nor the documented exclusions.\n"+
					"Decide, against the inclusion rule: does it change the Pod's runtime,\n"+
					"credentials, isolation, resource access, or placement eligibility?", what, name)
			}
			if included[name] && isExcluded {
				t.Errorf("%s.%s is listed as both included and excluded", what, name)
			}
		}
		// Catch stale entries: a field removed upstream should not linger.
		present := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			present[typ.Field(i).Name] = true
		}
		for name := range included {
			if !present[name] {
				t.Errorf("%s.%s is listed as included but no longer exists upstream", what, name)
			}
		}
		for name := range excluded {
			if !present[name] {
				t.Errorf("%s.%s is listed as excluded but no longer exists upstream", what, name)
			}
		}
	}
	check("PodSpec", reflect.TypeOf(corev1.PodSpec{}), v2IncludedPodSpecFields, v2ExcludedPodSpecFields)
	check("Container", reflect.TypeOf(corev1.Container{}), v2IncludedContainerFields, v2ExcludedContainerFields)
}

func v2DeploymentWith(mut func(*corev1.PodSpec)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "n", Name: "x"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "img"}},
		}}},
	}
	mut(&d.Spec.Template.Spec)
	return d
}

func v2Hash(t *testing.T, d *appsv1.Deployment) [32]byte {
	t.Helper()
	h, err := ConfigHashV2(NormalizeV2(d))
	if err != nil {
		t.Fatalf("ConfigHashV2: %v", err)
	}
	return h
}

// TestV2PreservesSemanticOrder asserts v2 does NOT sort lists whose order
// changes behaviour. v1 sorted containers and env names; repeating that would
// be a security defect.
func TestV2PreservesSemanticOrder(t *testing.T) {
	// Init containers run in sequence, so their order IS the execution plan.
	a := v2DeploymentWith(func(s *corev1.PodSpec) {
		s.InitContainers = []corev1.Container{{Name: "first", Image: "i"}, {Name: "second", Image: "i"}}
	})
	b := v2DeploymentWith(func(s *corev1.PodSpec) {
		s.InitContainers = []corev1.Container{{Name: "second", Image: "i"}, {Name: "first", Image: "i"}}
	})
	if v2Hash(t, a) == v2Hash(t, b) {
		t.Error("reordering init containers did not change the hash; their order is their execution order")
	}

	// Kubernetes expands $(VAR) using variables defined EARLIER in the list.
	c := v2DeploymentWith(func(s *corev1.PodSpec) {
		s.Containers[0].Env = []corev1.EnvVar{{Name: "A"}, {Name: "B"}}
	})
	d := v2DeploymentWith(func(s *corev1.PodSpec) {
		s.Containers[0].Env = []corev1.EnvVar{{Name: "B"}, {Name: "A"}}
	})
	if v2Hash(t, c) == v2Hash(t, d) {
		t.Error("reordering env vars did not change the hash; order decides $(VAR) expansion")
	}
}

// TestV2ExcludesDeliveryPolicy pins the deliberate exclusions, including the
// reversal on replicas.
func TestV2ExcludesDeliveryPolicy(t *testing.T) {
	base := v2DeploymentWith(func(*corev1.PodSpec) {})
	want := v2Hash(t, base)

	scaled := base.DeepCopy()
	n := int32(17)
	scaled.Spec.Replicas = &n
	if v2Hash(t, scaled) != want {
		t.Error("replicas affected the v2 hash; scaling changes no Pod's code, credentials or privileges, and an HPA would churn it")
	}

	rollout := base.DeepCopy()
	rollout.Spec.Paused = true
	rollout.Spec.MinReadySeconds = 30
	rollout.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	if v2Hash(t, rollout) != want {
		t.Error("rollout policy affected the v2 hash; it changes delivery, not what a converged instance can do")
	}

	noisy := base.DeepCopy()
	noisy.Annotations = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{...}"}
	noisy.Status = appsv1.DeploymentStatus{Replicas: 3}
	if v2Hash(t, noisy) != want {
		t.Error("annotations or status affected the v2 hash")
	}
}

// TestV2RecordsEnvSourcesNotValues pins that repointing a variable at a
// different Secret is visible while the Secret's contents never are.
func TestV2RecordsEnvSourcesNotValues(t *testing.T) {
	from := func(secret string) *appsv1.Deployment {
		return v2DeploymentWith(func(s *corev1.PodSpec) {
			s.Containers[0].Env = []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: "k",
				},
			}}}
		})
	}
	if v2Hash(t, from("secret-a")) == v2Hash(t, from("secret-b")) {
		t.Error("repointing an env var at a different Secret did not change the hash")
	}

	literal := func(v string) *appsv1.Deployment {
		return v2DeploymentWith(func(s *corev1.PodSpec) {
			s.Containers[0].Env = []corev1.EnvVar{{Name: "TOKEN", Value: v}}
		})
	}
	if v2Hash(t, literal("public")) != v2Hash(t, literal("super-secret")) {
		t.Error("an env VALUE affected the hash; values must never reach the hash, the logs or the chain")
	}

	// Swapping an inline value for a sourced one must still be visible.
	if v2Hash(t, literal("x")) == v2Hash(t, from("secret-a")) {
		t.Error("swapping a literal env var for a sourced one did not change the hash")
	}
}
