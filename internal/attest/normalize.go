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
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// defaultReplicas mirrors the Kubernetes default applied by the apiserver when
// spec.replicas is omitted. We normalize nil to this value so that an omitted
// field and an explicit "1" hash identically.
const defaultReplicas int32 = 1

// generatedLabelKeys are label keys written by controllers/tooling rather than
// by the author of the Deployment. They are non-deterministic across rollouts
// (e.g. pod-template-hash changes whenever the pod template changes) and would
// otherwise make the hash unstable, so they are excluded from BOTH the
// Deployment labels and the pod template labels.
var generatedLabelKeys = map[string]struct{}{
	"pod-template-hash":                        {},
	"controller-revision-hash":                 {},
	"pod-template-generation":                  {},
	"statefulset.kubernetes.io/pod-name":       {},
	"apps.kubernetes.io/pod-index":             {},
	"batch.kubernetes.io/job-completion-index": {},
}

// isGeneratedLabel reports whether a label key is controller/tooling generated
// and therefore excluded from the hash.
func isGeneratedLabel(key string) bool {
	_, ok := generatedLabelKeys[key]
	return ok
}

// Normalize projects an observed Deployment onto the documented, deterministic
// subset defined by NormalizedDeployment. It is pure: it reads only the fields
// listed below and performs no I/O. Annotations are excluded in their entirety
// (they are routinely mutated by kubectl apply, Helm, cert-manager, and service
// mesh injectors), as is all of status and all object metadata other than
// namespace, name, and non-generated labels.
func Normalize(d *appsv1.Deployment) NormalizedDeployment {
	replicas := defaultReplicas
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}

	return NormalizedDeployment{
		Namespace:         d.Namespace,
		Name:              d.Name,
		Labels:            filterLabels(d.Labels),
		Replicas:          replicas,
		Selector:          normalizeSelector(d.Spec.Selector),
		PodTemplateLabels: filterLabels(d.Spec.Template.Labels),
		Containers:        normalizeContainers(d.Spec.Template.Spec.Containers),
	}
}

// filterLabels copies labels minus the generated denylist. It always returns a
// non-nil map so that the JSON encoding is "{}" rather than "null", giving a
// single canonical form regardless of whether the input was nil or empty.
func filterLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if isGeneratedLabel(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// normalizeSelector copies matchLabels verbatim (it is user intent, not
// controller-generated) and sorts matchExpressions deterministically.
func normalizeSelector(sel *metav1.LabelSelector) NormalizedSelector {
	ns := NormalizedSelector{
		MatchLabels:      map[string]string{},
		MatchExpressions: []NormalizedSelectorReq{},
	}
	if sel == nil {
		return ns
	}
	for k, v := range sel.MatchLabels {
		ns.MatchLabels[k] = v
	}
	for _, req := range sel.MatchExpressions {
		values := append([]string(nil), req.Values...)
		sort.Strings(values)
		ns.MatchExpressions = append(ns.MatchExpressions, NormalizedSelectorReq{
			Key:      req.Key,
			Operator: string(req.Operator),
			Values:   values,
		})
	}
	sort.Slice(ns.MatchExpressions, func(i, j int) bool {
		if ns.MatchExpressions[i].Key != ns.MatchExpressions[j].Key {
			return ns.MatchExpressions[i].Key < ns.MatchExpressions[j].Key
		}
		return ns.MatchExpressions[i].Operator < ns.MatchExpressions[j].Operator
	})
	return ns
}

// normalizeContainers extracts the attested subset of each container and sorts
// the result by container name. Sorting removes ordering noise so two clusters
// that applied the same manifest hash identically even if the serialized
// container order differs.
func normalizeContainers(cs []corev1.Container) []NormalizedContainer {
	out := make([]NormalizedContainer, 0, len(cs))
	for _, c := range cs {
		out = append(out, NormalizedContainer{
			Name:      c.Name,
			Image:     c.Image,
			EnvNames:  envNames(c.Env),
			Resources: normalizeResources(c.Resources),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// envNames returns the sorted set of environment variable names. Values are
// deliberately never read, so an env var sourced from a Secret never leaks into
// the hash, logs, or the chain.
func envNames(env []corev1.EnvVar) []string {
	names := make([]string, 0, len(env))
	for _, e := range env {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names
}

// normalizeResources converts requests/limits into canonical quantity strings.
// resource.Quantity.String() yields a stable canonical form (e.g. "0.25" ->
// "250m"), and encoding/json sorts the resulting map keys, so the output is
// deterministic without further work.
func normalizeResources(r corev1.ResourceRequirements) NormalizedResources {
	return NormalizedResources{
		Requests: quantityMap(r.Requests),
		Limits:   quantityMap(r.Limits),
	}
}

func quantityMap(rl corev1.ResourceList) map[string]string {
	out := make(map[string]string, len(rl))
	for name, q := range rl {
		// Copy to take a stable canonical string without mutating the input.
		qc := q.DeepCopy()
		out[string(name)] = qc.String()
	}
	return out
}
