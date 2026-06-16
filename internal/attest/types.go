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

// Package attest is the single source of truth for turning an observed
// apps/v1.Deployment into a deterministic, hashable representation and for
// verifying signatures over that representation.
//
// This package is imported by BOTH the operator (which signs and publishes)
// and the verify CLI (which recomputes and checks). Keeping the logic in one
// package is what makes the verifier's recomputation provably identical to the
// operator's. Do not fork this logic.
//
// Trust boundary: this package only describes WHAT is hashed. It makes no claim
// that the cluster which produced the Deployment was honest. A compromised
// cluster or operator can present a benign Deployment to the normalizer; that
// is out of scope (see README "Trust boundary").
package attest

// NormalizedDeployment is the documented, deterministic subset of a Deployment
// that participates in the config hash. Fields NOT present here are excluded by
// design — see README "What fields are excluded and why". The JSON tags and the
// struct field order are part of the wire contract: changing either changes
// every hash this project has ever produced, so treat them as versioned.
type NormalizedDeployment struct {
	Namespace         string                `json:"namespace"`
	Name              string                `json:"name"`
	Labels            map[string]string     `json:"labels"`
	Replicas          int32                 `json:"replicas"`
	Selector          NormalizedSelector    `json:"selector"`
	PodTemplateLabels map[string]string     `json:"podTemplateLabels"`
	Containers        []NormalizedContainer `json:"containers"`
}

// NormalizedSelector captures the Deployment's pod selector. Both matchLabels
// and matchExpressions are included because both express user intent about
// which pods the Deployment owns.
type NormalizedSelector struct {
	MatchLabels      map[string]string         `json:"matchLabels"`
	MatchExpressions []NormalizedSelectorReq   `json:"matchExpressions"`
}

// NormalizedSelectorReq is a single set-based selector requirement. Values are
// sorted in Normalize to remove ordering noise.
type NormalizedSelectorReq struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// NormalizedContainer captures the attested subset of a single container.
// Crucially, only environment variable NAMES are captured — never values — so
// that secrets injected via env are never hashed, logged, or published.
type NormalizedContainer struct {
	Name      string              `json:"name"`
	Image     string              `json:"image"`
	EnvNames  []string            `json:"envNames"`
	Resources NormalizedResources `json:"resources"`
}

// NormalizedResources captures requests and limits as canonical quantity
// strings (e.g. "250m", "512Mi"). Keys are resource names (cpu, memory, ...).
type NormalizedResources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}
