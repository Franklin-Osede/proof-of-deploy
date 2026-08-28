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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// NormalizeV2 projects an observed Deployment onto the v2 hash surface.
//
// # On ordering
//
// v2 PRESERVES declared list order everywhere. v1 sorted containers and env
// names; repeating that here would be a security defect, not a convenience:
//
//   - initContainers run in sequence. Their order IS their execution order, so
//     sorting them would make two different execution plans hash identically.
//   - Kubernetes expands $(VAR) references in env values, command and args
//     using variables defined EARLIER in the list, so env order changes what a
//     container actually receives.
//
// Sorting is only ever justified when order is neither semantic nor stable.
// Here it is both: the apiserver returns list order as it was declared. Where
// server-side apply can still reorder a list, preserving order costs a noisy
// FAIL; sorting would cost a silent PASS over a changed workload. For an
// attestation system that trade is not close.
//
// Map keys need no handling: encoding/json emits them sorted.
//
// # On filtering
//
// Pod template labels are filtered through the generated-label denylist because
// controllers and tooling write there. Selector match labels are NOT filtered,
// and the asymmetry is deliberate rather than an oversight: nothing injects
// into a Deployment's selector, it is immutable in apps/v1, and filtering it
// would let two genuinely different selectors hash the same — a false PASS
// traded for no benefit.
func NormalizeV2(d *appsv1.Deployment) NormalizedDeploymentV2 {
	spec := d.Spec.Template.Spec
	return NormalizedDeploymentV2{
		Namespace:         d.Namespace,
		Name:              d.Name,
		Labels:            filterLabels(d.Labels),
		Selector:          normalizeSelector(d.Spec.Selector),
		PodTemplateLabels: filterLabels(d.Spec.Template.Labels),
		Pod: NormalizedPodSpec{
			InitContainers: normalizeContainersV2(spec.InitContainers),
			Containers:     normalizeContainersV2(spec.Containers),

			ServiceAccountName:           spec.ServiceAccountName,
			AutomountServiceAccountToken: spec.AutomountServiceAccountToken,
			ImagePullSecrets:             nonNilSlice(spec.ImagePullSecrets),

			HostNetwork: spec.HostNetwork,
			HostPID:     spec.HostPID,
			HostIPC:     spec.HostIPC,
			HostUsers:   spec.HostUsers,

			RuntimeClassName:      spec.RuntimeClassName,
			SecurityContext:       spec.SecurityContext,
			ShareProcessNamespace: spec.ShareProcessNamespace,

			Volumes:        nonNilSlice(spec.Volumes),
			ResourceClaims: nonNilSlice(spec.ResourceClaims),

			HostAliases:        nonNilSlice(spec.HostAliases),
			DNSPolicy:          spec.DNSPolicy,
			DNSConfig:          spec.DNSConfig,
			Hostname:           spec.Hostname,
			Subdomain:          spec.Subdomain,
			SetHostnameAsFQDN:  spec.SetHostnameAsFQDN,
			EnableServiceLinks: spec.EnableServiceLinks,

			NodeSelector:              nonNilMap(spec.NodeSelector),
			NodeName:                  spec.NodeName,
			SchedulerName:             spec.SchedulerName,
			Affinity:                  spec.Affinity,
			Tolerations:               nonNilSlice(spec.Tolerations),
			TopologySpreadConstraints: nonNilSlice(spec.TopologySpreadConstraints),
			PriorityClassName:         spec.PriorityClassName,
			PreemptionPolicy:          spec.PreemptionPolicy,
			SchedulingGates:           nonNilSlice(spec.SchedulingGates),
			OS:                        spec.OS,
		},
	}
}

// nonNilSlice returns an empty slice for nil input so the JSON encoding is "[]"
// rather than "null", giving one canonical form regardless of which the
// apiserver happened to return.
func nonNilSlice[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// nonNilMap is nonNilSlice for maps: "{}" rather than "null".
func nonNilMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}

// normalizeContainersV2 projects each container, preserving declared order.
func normalizeContainersV2(cs []corev1.Container) []NormalizedContainerV2 {
	out := make([]NormalizedContainerV2, 0, len(cs))
	for _, c := range cs {
		out = append(out, NormalizedContainerV2{
			Name:       c.Name,
			Image:      c.Image,
			Command:    nonNilSlice(c.Command),
			Args:       nonNilSlice(c.Args),
			WorkingDir: c.WorkingDir,

			Env:     normalizeEnvRefs(c.Env),
			EnvFrom: nonNilSlice(c.EnvFrom),

			Ports:           nonNilSlice(c.Ports),
			ImagePullPolicy: c.ImagePullPolicy,
			Resources:       normalizeResources(c.Resources),
			VolumeMounts:    nonNilSlice(c.VolumeMounts),
			VolumeDevices:   nonNilSlice(c.VolumeDevices),
			SecurityContext: c.SecurityContext,

			LivenessProbe:  c.LivenessProbe,
			ReadinessProbe: c.ReadinessProbe,
			StartupProbe:   c.StartupProbe,
			Lifecycle:      c.Lifecycle,
			RestartPolicy:  c.RestartPolicy,
		})
	}
	return out
}

// normalizeEnvRefs records each variable's name and where it comes from, never
// what it contains.
//
// v1 recorded names only, so repointing a variable from one Secret to another
// was invisible to the hash. Literal distinguishes an inline value from a
// sourced one without recording the value itself, so swapping one for the other
// is visible while a rotated Secret still is not.
func normalizeEnvRefs(env []corev1.EnvVar) []NormalizedEnvRef {
	out := make([]NormalizedEnvRef, 0, len(env))
	for _, e := range env {
		out = append(out, NormalizedEnvRef{
			Name:      e.Name,
			Literal:   e.ValueFrom == nil,
			ValueFrom: e.ValueFrom,
		})
	}
	return out
}

// CanonicalJSONV2 returns the deterministic JSON encoding of a v2 normalized
// Deployment. Compact, never indented: whitespace is part of the digest.
func CanonicalJSONV2(nd NormalizedDeploymentV2) ([]byte, error) {
	return jsonMarshal(nd)
}

// ConfigHashV2 is the SHA-256 over the canonical v2 JSON.
func ConfigHashV2(nd NormalizedDeploymentV2) ([32]byte, error) {
	b, err := CanonicalJSONV2(nd)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256Sum(b), nil
}
