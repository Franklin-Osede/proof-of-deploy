# ADR 0001 — Versioning the hash protocol and defining v2

**Status:** Decision 0 implemented. Decisions 1–4 proposed.
**Supersedes:** nothing. v1 is the format frozen in `internal/attest/testdata`.

> Decision 0 (version representation) is implemented: the contract stores
> `hashVersion`, the signed digest binds it, and the verifier refuses versions
> it does not implement. The v1 hash surface is unchanged — Decisions 1–4 are
> still open, and the surface list in Decision 1 is the part most worth
> arguing with before any of it is written.

## Context

v1 hashes a narrow slice of a Deployment: namespace, name, non-generated
labels, replicas, selector, pod template labels, and for each *normal* container
its name, image string, env var **names**, and resource requests/limits.

`config/samples/demo-deployment-tampered.yaml` is byte-identical to the benign
sample in every one of those fields, and materially more dangerous in every
field v1 omits. Both hash to
`89ab57526b689c52761431af4bc5451933c1947b74e0db262438ad1881c17a77`, and both
verify as `PASS`. This was demonstrated on a live cluster and is pinned as a
regression test.

So a `PASS` today means roughly *"the same named containers, from the same image
tags, with the same env var names and resource envelope"*. It is not evidence
about what the workload does or what it is permitted to do. For a project named
"proof of deploy", that gap is the main credibility problem.

Two determinism defects found while freezing v1 have already been fixed
(quantities now canonicalize by value, selector requirements sort fully). Those
were corrections, not surface changes. This ADR is about surface, identity and
versioning.

## Decision 0 — Where the version lives

**This is the decision that gates every other one, and it is not free.**

A verifier recomputes the hash from the live Deployment. To do that it must
first know *which normalizer to run*. Therefore:

- The version **cannot** live only inside the hashed JSON. Reading it would
  require producing the JSON, which requires already knowing the version.
- The version **must not** be inferred from the shape of the JSON. Shape
  sniffing turns a protocol into a guessing game and silently misverifies the
  moment two versions become shape-compatible.

That leaves the version as data the verifier obtains *alongside* the
attestation, which means on-chain.

### Options

**A. Add a `uint16 hashVersion` field to the `Attestation` struct.**
Explicit, one storage slot, trivially readable, and impossible to misinterpret.
Requires deploying a new contract — but the current one has an **immutable**
`publisher` and no upgrade path, so any change at all already means a new
deployment and a new address to distribute.

**B. Encode the version in the `deploymentId` key.**
Avoids a struct change but conflates identity with format, and silently
partitions history: the same Deployment would occupy two unrelated slots.
Rejected.

**C. Keep it off-chain, supplied to the verifier by configuration.**
No contract change, but the verifier's most security-relevant input becomes a
flag a human sets. A wrong `--hash-version` produces a confident wrong answer.
Rejected.

**D. Prefix the signed payload with a version byte, sign `version || configHash`.**
Binds the version cryptographically, which A alone does not. But the verifier
still needs the version *before* recomputing, so this is a complement to A, not
a substitute.

### Proposed

**A, combined with D.** Store `hashVersion` explicitly on-chain so the verifier
can read it before recomputing, and include it in the signed bytes so a
tampered version field is detectable rather than merely wrong.

The verifier **must reject unknown versions outright**. It must never try v1,
then v2, then report whichever matched: that converts an unknown format into a
downgrade oracle and would let an attacker who can write on-chain steer a
verifier onto the weaker surface.

**Consequence to accept up front:** this requires a new contract deployment and
a new address distributed to every consumer. Given the immutable publisher, that
cost is already unavoidable for any change and should not be spent twice —
batching, append-only history and any other storage change worth making should
be decided before the redeploy, not after.

## Decision 1 — The v2 surface

v2 hashes the executable and privilege-relevant shape of the pod, for **both**
`containers` and `initContainers`:

| Included | Why |
|---|---|
| `image` | already in v1 |
| `command`, `args` | a different program from the same image |
| `env` names **and** their **source** (`valueFrom` ref), plus `envFrom` refs | which Secret/ConfigMap feeds the process |
| `volumeMounts` and the `volumes` they resolve to | `hostPath`, Secret and ConfigMap exposure |
| `securityContext` (pod and container) | `privileged`, capabilities, `runAsUser`, `allowPrivilegeEscalation` |
| `ports`, `workingDir`, `imagePullPolicy` | observable execution surface |
| probes and lifecycle hooks | arbitrary execution paths |
| `resources` | already in v1 |
| `serviceAccountName`, `automountServiceAccountToken` | cluster identity granted to the workload |
| `hostNetwork`, `hostPID`, `hostIPC` | host namespace escape surface |
| `nodeSelector`, `affinity`, `tolerations`, `runtimeClassName` | where and under what runtime it lands |

Still excluded, deliberately: all annotations, all `status`, and env var
**values** — the last so a Secret can never enter the hash, the logs, or a
public chain. Recording that a variable *comes from* a given Secret is in
scope; recording what that Secret contains is not.

**Open question, not decided here:** whether `strategy`, `paused`,
`minReadySeconds` and `progressDeadlineSeconds` belong in v2. They change
rollout behaviour but not the running workload's privileges.

## Decision 2 — Logical identity vs incarnation

**UID stays out of `ConfigHash`.** A UID describes *which instance* of an object
this is, not *what was configured*. Two reasons:

1. It is not configuration. Mixing it in would mean an identical redeploy
   produces a different hash, which destroys the property that the hash
   describes declared intent.
2. It would make manifests unverifiable from Git, where no UID exists. Being
   able to compare a repository's declared intent against the chain is worth
   keeping reachable.

But incarnation still matters. `DeploymentID` is `SHA-256("namespace/name")`
with no incarnation, so between a delete/recreate and the new transaction being
mined, `pod-verify` matches a fresh object against its predecessor's record and
returns `PASS`. The in-memory dedup fix narrowed that window; it did not close
it.

**Proposed:** model incarnation as identity metadata *outside* the config hash —
a separate field recorded with the attestation. This keeps the hash purely about
configuration while letting a verifier detect that it is looking at a different
instance than the one attested. The exact shape (UID, `creationTimestamp`, a
monotonic counter) is deferred; note that a Git-manifest verifier would simply
have no value to compare, which is correct rather than a failure.

`DeploymentID`'s other weakness is recorded in `TestDeploymentIDFormat`: it is
not injective on arbitrary strings, and is safe only because Kubernetes names
cannot contain `/`. Any richer v2 identity must use an unambiguous encoding
rather than inherit that.

## Decision 3 — Images

**Hash the declared image string. Do not resolve tags in the operator.**

Resolving a tag to a digest would make the attestation stronger, but it makes
the **registry** and the **instant of resolution** into new roots of trust: the
operator would be attesting something it learned from a third party at a moment
nobody can reproduce. That is a larger change to the trust model than it looks,
and it belongs in its own ADR if wanted.

Instead: v2 keeps hashing the declared value, and the project **recommends**
pinning by digest (`image: repo/app@sha256:...`). The sample workload already
does. A future option is to record the declared string and any separately
resolved digest as **distinct** fields, so a reader can see which is which.

**Consequence to state plainly in the README:** with a floating tag, the bytes
behind `repo/app:latest` can change with no hash change and no `FAIL`. v2 does
not fix this; pinning by digest does.

## Decision 4 — v1/v2 compatibility

- **Verification:** v1 stays supported for reading historical records only, and
  is labelled in output as a weak surface. A `PASS` against a v1 attestation
  should say so.
- **Publication:** once v2 exists, the operator publishes v2 only. No dual
  publication — it doubles gas and creates two answers to one question.
- **Unknown versions are a hard error.** Never a fallback, never a heuristic.
- **Golden vectors:** the v1 set stays exactly as it is. v2 gets its own set,
  and the benign/tampered pair moves into it with the assertion **inverted**:
  the two must hash *differently* under v2. `TestV1WeaknessIsPinned` is written
  to fail the moment the surface widens, which is the intended trigger for that
  move.

## Consequences

- A new contract deployment and a new address for every consumer.
- Every v1 attestation becomes historical; nothing migrates.
- `internal/attest` grows substantially, and so does its blast radius. The
  golden set is what makes that tractable.
- The demo gains its real ending: the tampered workload finally produces `FAIL`.

## Not decided here

Append-only history vs latest-only, batching, publisher key rotation, and
whether to attest kinds other than Deployment. All of these interact with the
redeploy forced by Decision 0 and should be settled before it, not after.
