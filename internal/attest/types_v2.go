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

import corev1 "k8s.io/api/core/v1"

// The v2 hash surface.
//
// The question v2 answers is: DOES THIS WORKLOAD EXECUTE, AND IS IT PERMITTED
// TO DO, WHAT WAS ATTESTED? Not "is this Deployment identical in every declared
// field". The narrower claim is more defensible and far more stable.
//
// Inclusion rule, from docs/adr/0001-hash-protocol-v2.md: a field is included
// when it is a declarative field that changes the Pod's runtime, credentials,
// isolation, resource access, or placement eligibility. Every future field is
// argued against that rule, not appended to a list.
//
// Deliberately EXCLUDED, each for a stated reason:
//
//   - replicas, strategy, paused, minReadySeconds, progressDeadlineSeconds.
//     They change how a workload is delivered, not what a converged instance
//     can do. replicas additionally churns under an HPA, which would mean a
//     fresh hash, a KMS call and a transaction on every scaling event.
//   - all annotations and all of status.
//   - environment variable VALUES. Names and sources are attested; contents
//     never touch the hash, the logs, or a public chain.
//
// v2 attests execution and privilege. It does NOT attest capacity, cost,
// availability or scale.
//
// Struct field order and JSON tags are the wire format. Changing either is a
// protocol change; golden vectors pin them.
type NormalizedDeploymentV2 struct {
	Namespace         string             `json:"namespace"`
	Name              string             `json:"name"`
	Labels            map[string]string  `json:"labels"`
	Selector          NormalizedSelector `json:"selector"`
	PodTemplateLabels map[string]string  `json:"podTemplateLabels"`
	Pod               NormalizedPodSpec  `json:"pod"`
}

// NormalizedPodSpec is the attested projection of a PodSpec.
//
// Deeply nested values (security contexts, volumes, affinity, probes) embed the
// upstream Kubernetes types rather than mirroring them. Their internal shape is
// not a decision this project makes, and hand-mirroring them would be a large
// surface on which to silently drop a field. The cost is that an upstream type
// change alters the hash — which the golden vectors turn into a loud failure
// rather than a silent one, and which is the correct outcome for a wire format.
type NormalizedPodSpec struct {
	InitContainers []NormalizedContainerV2 `json:"initContainers"`
	Containers     []NormalizedContainerV2 `json:"containers"`

	// Identity the workload runs as.
	ServiceAccountName           string                        `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool                         `json:"automountServiceAccountToken"`
	ImagePullSecrets             []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// Host namespace escape surface.
	HostNetwork bool  `json:"hostNetwork"`
	HostPID     bool  `json:"hostPID"`
	HostIPC     bool  `json:"hostIPC"`
	HostUsers   *bool `json:"hostUsers"`

	// Isolation.
	RuntimeClassName      *string                    `json:"runtimeClassName"`
	SecurityContext       *corev1.PodSecurityContext `json:"securityContext"`
	ShareProcessNamespace *bool                      `json:"shareProcessNamespace"`

	// What the workload can reach.
	Volumes        []corev1.Volume           `json:"volumes"`
	ResourceClaims []corev1.PodResourceClaim `json:"resourceClaims"`

	// Name resolution: these redirect traffic, so they are a security property.
	HostAliases       []corev1.HostAlias   `json:"hostAliases"`
	DNSPolicy         corev1.DNSPolicy     `json:"dnsPolicy"`
	DNSConfig         *corev1.PodDNSConfig `json:"dnsConfig"`
	Hostname          string               `json:"hostname"`
	Subdomain         string               `json:"subdomain"`
	SetHostnameAsFQDN *bool                `json:"setHostnameAsFQDN"`
	// EnableServiceLinks injects service discovery variables into every
	// container, so it changes what the process actually receives.
	EnableServiceLinks *bool `json:"enableServiceLinks"`

	// Placement eligibility, and the ability to displace other workloads.
	NodeSelector              map[string]string                 `json:"nodeSelector"`
	NodeName                  string                            `json:"nodeName"`
	SchedulerName             string                            `json:"schedulerName"`
	Affinity                  *corev1.Affinity                  `json:"affinity"`
	Tolerations               []corev1.Toleration               `json:"tolerations"`
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
	PriorityClassName         string                            `json:"priorityClassName"`
	PreemptionPolicy          *corev1.PreemptionPolicy          `json:"preemptionPolicy"`
	SchedulingGates           []corev1.PodSchedulingGate        `json:"schedulingGates"`
	OS                        *corev1.PodOS                     `json:"os"`
}

// NormalizedContainerV2 is the attested projection of a single container, used
// identically for containers and initContainers.
//
// The v1 version of this carried only name, image, env NAMES and resources,
// which is why a workload could be made privileged, given the host filesystem
// and told to run a different program while hashing the same.
type NormalizedContainerV2 struct {
	Name  string `json:"name"`
	Image string `json:"image"`

	// A different program from the same image.
	Command    []string `json:"command"`
	Args       []string `json:"args"`
	WorkingDir string   `json:"workingDir"`

	// Where a variable comes from is attested; what it contains is not.
	Env     []NormalizedEnvRef     `json:"env"`
	EnvFrom []corev1.EnvFromSource `json:"envFrom"`

	Ports           []corev1.ContainerPort  `json:"ports"`
	ImagePullPolicy corev1.PullPolicy       `json:"imagePullPolicy"`
	Resources       NormalizedResources     `json:"resources"`
	VolumeMounts    []corev1.VolumeMount    `json:"volumeMounts"`
	VolumeDevices   []corev1.VolumeDevice   `json:"volumeDevices"`
	SecurityContext *corev1.SecurityContext `json:"securityContext"`

	// Arbitrary execution paths.
	LivenessProbe  *corev1.Probe     `json:"livenessProbe"`
	ReadinessProbe *corev1.Probe     `json:"readinessProbe"`
	StartupProbe   *corev1.Probe     `json:"startupProbe"`
	Lifecycle      *corev1.Lifecycle `json:"lifecycle"`

	// RestartPolicy at CONTAINER level is what turns an init container into
	// a sidecar that keeps running alongside the app. That is execution
	// semantics, not delivery policy, which is why it is attested here while
	// the pod-level RestartPolicy is not.
	RestartPolicy *corev1.ContainerRestartPolicy `json:"restartPolicy"`
}

// NormalizedEnvRef records an environment variable's NAME and, when it is
// sourced from elsewhere, WHERE FROM — never its value.
//
// v1 recorded only names, so repointing a variable from one Secret to another
// was invisible. The value itself stays excluded so a Secret can never enter
// the hash, the logs, or a public chain.
type NormalizedEnvRef struct {
	Name string `json:"name"`
	// Literal is true when the value was given inline rather than sourced.
	// The value itself is never recorded; this only distinguishes "inline" from
	// "sourced", so swapping one for the other is visible.
	Literal   bool                 `json:"literal"`
	ValueFrom *corev1.EnvVarSource `json:"valueFrom"`
}
