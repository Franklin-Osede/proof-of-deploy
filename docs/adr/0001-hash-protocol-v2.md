# ADR 0001 — Protocol v2: signed envelope, identity, and hash surface

**Status:** accepted. Decision 0 is implemented; Decisions 1–8 are accepted and
not yet implemented.
**Supersedes:** nothing. v1 is the format frozen in `internal/attest/testdata`.

## Context

v1 hashes a narrow slice of a Deployment: namespace, name, non-generated
labels, replicas, selector, pod template labels, and for each *normal* container
its name, image string, env var **names**, and resource requests/limits.

`config/samples/demo-deployment-tampered.yaml` is byte-identical to the benign
sample in every one of those fields, and materially more dangerous in every
field v1 omits. Both hash to
`89ab57526b689c52761431af4bc5451933c1947b74e0db262438ad1881c17a77` and both
verify as `PASS`. This was demonstrated on a live cluster and is pinned by
`TestV1WeaknessIsPinned`.

So a v1 `PASS` means roughly *"the same named containers, from the same image
tags, with the same env var names and resource envelope"*. It is not evidence
about what the workload does or what it is permitted to do.

v1 also has no notion of **which cluster** it is talking about, and no notion of
**which incarnation** of an object was observed. Both turn out to be as
load-bearing as the hash surface itself.

## Decision 0 — Where the version lives *(implemented)*

A verifier recomputes the hash from the live Deployment, so it must know which
normalizer to run *before* it can produce any bytes to compare. A version
carried only inside the hashed payload is unreachable at that moment, and
inferring it from the payload's shape misverifies as soon as two versions become
shape-compatible.

The version is therefore stored on-chain, bound into the signed digest, and
unknown versions are a hard error — never a fallback, because trying each
version in turn is a downgrade oracle for anyone able to write on-chain.

Implemented in `internal/attest/version.go`, `AttestationRegistry.sol` and
`cmd/verify`. **Decision 3 below extends the signed digest and supersedes the
current `SigningDigest` shape.**

## Decision 1 — What v2 hashes

### The question v2 answers

> *Does this workload execute, and is it permitted to do, what was attested?*

Not *"is this Deployment identical in every declared field"*. The narrower claim
is more defensible, more stable, and lets rollout-shaped fields be excluded for
a stated reason rather than by omission.

### The inclusion rule

A list is an accident; a rule is a decision. Fields are included when they are
**declarative fields that change the Pod's runtime, credentials, isolation,
resource access, or placement eligibility.**

Every future field is argued against that rule, not against this list.

### Included

For **both** `containers` and `initContainers`: `name`, `image`, `command`,
`args`, `workingDir`, `ports`, `imagePullPolicy`, `resources`, env var **names**
plus their `valueFrom` references, `envFrom` references, `volumeMounts`,
`securityContext`, probes and lifecycle hooks.

At pod level: `securityContext`, `volumes`, `serviceAccountName`,
`automountServiceAccountToken`, `hostNetwork`, `hostPID`, `hostIPC`,
`runtimeClassName`, `nodeSelector`, `affinity`, `tolerations`.

Pod template labels stay in: NetworkPolicies select by pod label, so a label
change can change which policy applies.

**Evaluated against the rule during implementation**, all eight included:
`schedulerName` and `nodeName` decide placement; `topologySpreadConstraints`
likewise; `priorityClassName` and `preemptionPolicy` let a workload displace
others; `hostAliases`, `dnsPolicy` and `dnsConfig` change name resolution and
therefore redirect traffic.

Writing the surface also produced `TestV2SurfaceAccountsForEveryField`, which
reflects over the upstream `PodSpec` and `Container` and fails when a field is
in neither the attested surface nor the documented exclusions. It is what makes
an allowlist defensible: without it a field added upstream is silently absent
from the hash and nothing fails. It immediately caught eight that had been
missed — `imagePullSecrets`, `shareProcessNamespace`, `hostUsers`,
`resourceClaims`, `enableServiceLinks`, `schedulingGates`, `os`, and the
container-level `restartPolicy` that distinguishes a sidecar from a plain init
container — all of which are now included.

**Ordering.** v2 preserves declared list order everywhere. v1 sorted containers
and env names; repeating that would be a security defect rather than a
convenience. Init containers run in sequence, so sorting them would make two
different execution plans hash identically, and Kubernetes expands `$(VAR)`
using variables defined earlier in the env list. Sorting is justified only when
order is neither semantic nor stable; here it is both.

### Excluded, with reasons

- **`replicas`.** Reversing v1. Scaling does not change a Pod's code,
  credentials, filesystem, namespaces or privileges, and an HPA rewrites it
  continuously — every stabilization would mean a fresh hash, a KMS call and a
  transaction. Once out, a post-scaling reconcile recomputes the same hash and
  dedup suppresses the publish.
- **`strategy`, `paused`, `minReadySeconds`, `progressDeadlineSeconds`.** They
  change how a workload is *delivered*, not what a converged instance can do.
- **All annotations, all `status`,** and **env var values** — the last so a
  Secret can never enter the hash, the logs, or a public chain. Recording that a
  variable comes *from* a given Secret is in scope; its contents are not.

### What v2 explicitly does not claim

v2 attests **execution and privilege**, not capacity, cost, availability or
scale. Going from 3 to 5 replicas can amplify a malicious workload and does
affect cost; that belongs to a different claim — a rollout/capacity attestation —
and must not contaminate `ConfigHashV2`.

Scheduling fields are included because placement is a real security boundary for
organisations that use it as one. They are the most likely source of noisy
`FAIL`s, and unlike `replicas` they are not rewritten automatically.

## Decision 2 — Identity and incarnation

Three distinct things, currently conflated into `SHA-256("namespace/name")`:

```
cluster identity  = which cluster this was observed in
logical identity  = clusterID + apiVersion + kind + namespace + name
incarnation       = the Kubernetes UID of the specific object observed
```

### clusterID is mandatory

Without it, `payments/api` in cluster A and `payments/api` in cluster B occupy
the same on-chain slot and overwrite each other. `pod-verify` printing the
kubeconfig context does not fix this: that string is local, mutable and bound to
nothing.

clusterID must be **explicitly configured**, stable for the cluster's lifetime,
part of the on-chain key, part of the signed envelope, and displayed by
`pod-verify`. It must **not** be derived from the kubeconfig context name. A
managed string/`bytes32` is adequate for the demo; how it is distributed and why
a verifier should trust it must be documented.

### Encoding

`WorkloadIdentityV2 { clusterID, apiVersion, kind, namespace, name }`, with an
**unambiguous** encoding — not informal `/` concatenation.
`TestDeploymentIDFormat` already pins that v1's construction is not injective on
arbitrary strings and is safe only because Kubernetes names cannot contain `/`.
v2 must not inherit that.

### UID stays out of the config hash — and must be signed

UID describes *which instance*, not *what was configured*. Inside `ConfigHash`
it would make an identical redeploy hash differently, and would make manifests
unverifiable from Git where no UID exists.

But **storing it on-chain without signing it is worth nothing.** A compromised
publisher EOA could pair a valid KMS signature with a different UID, which
defeats the entire separation between the EOA that writes and the KMS key that
attests. UID goes in the signed envelope.

### Verifier output

| Source | UID | Result |
|---|---|---|
| live cluster | matches | `PASS` |
| live cluster | differs | `FAIL` — a different incarnation |
| Git manifest | absent | **not** a full `PASS` |

A manifest check must not print the same `PASS` as a live check. Something like:

```
CONFIG MATCH  payments/api
  incarnation: NOT VERIFIED (manifest has no Kubernetes UID)
```

or an explicit `--manifest` mode with its own contract. Omitting the UID is
legitimate; it just yields a weaker guarantee, and the output has to say so.

## Decision 3 — The signed envelope

Conceptually:

```
signedDigest = SHA-256(
    "proof-of-deploy"     ||   // domain separation
    protocolVersion       ||
    clusterID             ||
    apiVersion || kind    ||
    namespace  || name    ||
    uid                   ||   // incarnation
    configHash                 // Decision 1's surface
)
```

Everything a verifier must not be able to swap independently of the signature is
bound here. The current implementation binds only domain, version and config
hash; it is insufficient for v2 and will be replaced.

The exact byte encoding must be **unambiguous** — length-prefixed or otherwise
non-concatenative, so no two distinct field tuples can produce the same
preimage — and covered by golden vectors before any of it is written.

Implemented as: a 4-byte big-endian length before every variable-length field,
a distinct NUL-terminated domain string per digest kind, and the fixed-width
config hash last. `EnvelopeV2.SigningPreimage` is exported so golden vectors pin
the bytes themselves rather than only their digest — a change that happened to
collide would otherwise be invisible. The incarnation is `SHA-256` over the UID
rather than the raw UID, because the Kubernetes API types a UID as an opaque
string and a fixed-width on-chain field must not depend on it being a UUID; the
all-zero value is reserved for "no incarnation bound".

## Decision 4 — Images

**Hash the declared reference. Do not resolve tags in the operator.**

Hashing what was declared preserves a reproducible claim: *"the Deployment
declared exactly this reference."* Resolving would fold in a second, different
claim: *"this registry returned this digest at this instant"* — making the
registry and the moment of resolution new roots of trust, and attesting
something the operator learned from a third party in a moment nobody can
reproduce.

The verifier classifies the reference by **structured parsing**, not string
matching:

| Form | Meaning |
|---|---|
| `repo/app@sha256:…` | declaratively pinned |
| `repo/app:v1.2.3` | mutable tag |
| `repo/app` or `repo/app:latest` | mutable and especially ambiguous |

and warns on the mutable cases, the same way a v1 `PASS` warns about its
surface.

**Even a digest does not license "these exact bytes ran."** The digest may
address a multi-architecture manifest list, from which the runtime selects a
platform-specific image. Far better than a tag; still not runtime attestation.

## Decision 5 — v1/v2 compatibility

- The operator publishes **v2 only**. No dual publication.
- Unknown versions remain a hard error.
- A v1 `PASS` requires an explicit `--allow-v1`. A warning was right while v1
  was the only option; once there is an alternative, accepting the weak surface
  must be a deliberate act.
- v1 output keeps saying its surface is weak.

**Correction of terminology:** v1 is not supported for "reading history". The
contract is latest-only, so what survives is the `latest` slot of a known v1
contract plus its events — and those events do not carry the signature. v1 is
supported for verifying **records still readable in known v1 contracts**, which
is a much narrower statement.

## Decision 6 — Storage and events

Keep **latest-only storage**, and make the **event self-sufficient**: workload
identity (including clusterID), UID/incarnation, hash version, config hash,
signer fingerprint, **signature**, and timestamp.

Log data is cheaper than storage, and carrying the signature is what makes a
historical attestation reconstructible at all — the current event omits it, so
superseded v1 records are unrecoverable. A test must assert the event and the
stored record carry exactly the same values.

Limits this does **not** overcome, and which the README must state:

- contracts cannot read logs, so this is for off-chain verifiers only;
- a historical verifier needs an RPC with unpruned logs, or an indexer;
- reorg and finality still apply;
- *reconstructible* is not *guaranteed available*.

## Decision 7 — Batching: deferred

Not built now. First ship the cheap fixes that reduce the volume:

- opt-in annotation (`proof-of-deploy.dev/attest: "true"`);
- namespace allowlist/selector;
- exclusion of the operator's own namespace by default;
- volume and cost metrics.

Then **measure** before designing anything: selected Deployments, rollouts/day,
publications/day, gas per publication, peak backlog, monthly testnet cost.
Merkle batching must be justified by observed volume, not by a hypothesis about
thousands of Deployments.

## Decision 8 — Publisher stays immutable

A rotatable `owner` would add exactly the administrative power this design
avoids, and would cost the property that the contract is small enough to audit
at a glance.

Consequences, to be stated plainly:

- loss or compromise means a **new contract**;
- a new address, and probably a new code hash, must be redistributed;
- consumers depend on a versioned distribution of that address;
- never mainnet, never real funds.

## Consequences

- A new contract deployment and a new address for every consumer. The publisher
  is immutable, so this was already unavoidable — the point is to settle the v2
  record layout (version, cluster identity, UID, self-sufficient event) *before*
  it, so the cost is paid once. Batching can wait: it would likely arrive as a
  separate entry point, and probably a separate contract, either way.
- Every v1 attestation becomes historical. Nothing migrates.
- `internal/attest` grows substantially, and so does its blast radius. The
  golden set is what keeps that tractable.
- The demo gains its real ending: the tampered workload finally `FAIL`s.

## Implementation order

Deliberately **not** starting with the normalizer.

1. ~~Define the exact v2 structures: `WorkloadIdentityV2`, the envelope, and the
   byte encoding of each.~~ Done — `internal/attest/identity.go`,
   `internal/attest/envelope.go`.
2. ~~Golden vectors for identity encoding, UID handling and the signed digest.~~
   Done — `internal/attest/testdata/_envelope_v2`, plus injectivity,
   field-binding and domain-separation tests. Verified non-vacuous: replacing
   length prefixing with either naive concatenation fails the injectivity test
   on the exact cases it was written for.
3. ~~Contract v2 and its tests, against those vectors.~~ Done —
   `contracts/contracts/AttestationRegistryV2.sol`. The Hardhat tests read the
   Go golden vectors from `internal/attest/testdata/_envelope_v2/reference.txt`
   rather than inventing their own, so a disagreement about widths or encoding
   between the two sides fails a test instead of surfacing on a real chain.
4. ~~`NormalizeV2` and its own golden set, with the benign/tampered pair moved
   across and its assertion **inverted**.~~ Done — `internal/attest/normalize_v2.go`.
   The pair is equal under v1 and unequal under v2, asserted by
   `TestV2DetectsTheTamperedWorkload`.
5. Operator and CLI.

Writing the normalizer first risks discovering late that the contract, KMS and
CLI each signed a different notion of identity.

## Resolved during implementation

The `Selector.MatchLabels` filtering asymmetry is **correct and kept**. Pod
template labels are filtered through the generated-label denylist because
controllers and tooling write there; nothing injects into a Deployment's
selector, which is immutable in `apps/v1`. Making it symmetric would let two
genuinely different selectors hash the same — a false PASS traded for no
benefit. Documented in `NormalizeV2` rather than left to look like an oversight.

## Still open

`CurrentVersion` remains v1: `NormalizeV2` exists and v2 records verify, but the
operator and chain client are not yet wired to the v2 contract. Flipping it
before that would publish v2 hashes into a v1 registry. That is step 5.
