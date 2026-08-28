# ADR 0002 — v2 wire encoding, field resolution, and the verifier contract

**Status:** proposed.
**Extends:** ADR 0001, which is accepted. This resolves the three things 0001
deferred: the eight fields left "to be evaluated against the rule", the exact
byte encoding it required to be unambiguous, and the verifier output contract it
described only in prose.

Nothing here changes an accepted decision. It makes 0001 implementable, which is
its own step 1.

## Context

0001 leaves three gaps that all have the same failure mode — they are settled
implicitly, by whoever writes the code first, and the disagreement surfaces only
after something is signed:

1. Eight scheduling-adjacent fields are deferred to a rule that, as written,
   does not decide them.
2. The signed digest is specified as `a || b || c` with a note that the real
   encoding "must be unambiguous". Concatenation is exactly what is not.
3. Manifest-mode output "must not print the same `PASS`", but `pod-verify`
   currently has one non-zero exit (`main.go:88`) shared by semantic failure and
   operational error, so any caller that branches on the exit code cannot tell
   a weaker guarantee from a stronger one regardless of what is printed.

## Decision 1 — Tighten the inclusion rule so it decides

0001's rule: *declarative fields that change the Pod's runtime, credentials,
isolation, resource access, or placement eligibility.*

"Placement eligibility" is doing too much work. It reads as admitting
`priorityClassName` and `preemptionPolicy`, which do not change where a Pod may
run — they change who loses when nodes are contended. Since 0001 already
disclaims availability and capacity, admitting them would contradict it.

**Revised rule, in two parts.**

A field is **in scope** when it changes either:

- **capability** — what a converged Pod can do: its code, arguments,
  credentials, isolation boundary, resource access, or name resolution; or
- **eligibility** — the set of nodes the Pod may be placed on, or who decides
  that placement.

A field is **out of scope** when it only affects:

- **delivery** — how the workload is rolled out;
- **scale** — how many instances exist;
- **contention** — who is preempted or evicted when capacity is short.

Name resolution is named explicitly because it is an isolation boundary that
does not look like one: redirecting a hostname the workload already trusts
needs no new privilege.

### The eight deferred fields, resolved

| Field | Decision | Reason under the rule |
|---|---|---|
| `dnsPolicy` | **in** | Changes name resolution. `ClusterFirst` → `None` with a custom `dnsConfig` moves every lookup to a resolver of the author's choosing. |
| `dnsConfig` | **in** | Injects nameservers, search domains and options. Redirection surface with no privilege change. |
| `hostAliases` | **in** | Writes `/etc/hosts` entries, redirecting a hostname the workload already trusts. |
| `topologySpreadConstraints` | **in** | A placement constraint in the same family as `affinity`, already included. Excluding it would let spread be relaxed without changing the hash. |
| `schedulerName` | **in** | Moves the eligibility decision to a different scheduler — possibly one the cluster owner does not control. Eligibility, by delegation. |
| `nodeName` | **in** | Bypasses the scheduler and pins the Pod to a node. The strongest possible placement statement; excluding it while including `nodeSelector` would be incoherent. |
| `priorityClassName` | **out** | Governs preemption and eviction order under contention. Contention, not eligibility. |
| `preemptionPolicy` | **out** | Same, and only meaningful together with priority. |

The two exclusions are consistent with `replicas`: v2 does not attest
availability, and priority only determines what happens when availability is
already at risk.

### The `MatchLabels` asymmetry

0001 lists this as still open: pod template labels are filtered through the
generated-label denylist, `Selector.MatchLabels` is not.

**Resolve toward symmetry, and prefer filtering neither.** On a *Deployment*,
both `spec.selector.matchLabels` and `spec.template.metadata.labels` are
author-written; the controller injects `pod-template-hash` into the ReplicaSet
it creates, not into the Deployment it read. If that is true in practice, the
denylist removes signal from a field where a change is meaningful — labels
select NetworkPolicies, which 0001 already cites as the reason to keep template
labels.

This must be **confirmed against a live Deployment and pinned by a fixture
before the denylist is removed**, not assumed. If some controller does write a
generated label onto a Deployment's template, filtering both sides symmetrically
is the fallback. Either outcome is acceptable; the asymmetry is not.

## Decision 2 — The exact encoding

The digest is produced by the operator and re-derived by the verifier. Both are
Go today, which makes an under-specified encoding *more* dangerous, not less:
two call sites in one language drift silently, and nothing fails until a
signature is checked against a record no one can reproduce.

### Primitives

```
lp(s)  = u32be(len(s)) || s          // length-prefixed, raw UTF-8, no normalization
u16be  = 2-byte big-endian
```

Every variable-length field is length-prefixed, so no two distinct field tuples
can share a preimage. `configHash` is fixed at 32 bytes and placed last, so it
needs no prefix.

### Logical identity — the on-chain key

```
workloadID = SHA-256(
    "proof-of-deploy/workload/v2\x00"
    || lp(clusterID)
    || lp(apiVersion)
    || lp(kind)
    || lp(namespace)
    || lp(name)
)
```

`uid` is deliberately absent: `workloadID` addresses the *logical* workload, so
the `latest` slot follows it across incarnations. Which incarnation currently
occupies that slot is stated by the envelope, not by the key. This is 0001's
logical-identity/incarnation split expressed in the two places it has to appear.

### Signed digest

```
signedDigest = SHA-256(
    "proof-of-deploy/attestation/v2\x00"
    || u16be(protocolVersion)
    || lp(clusterID)
    || lp(apiVersion)
    || lp(kind)
    || lp(namespace)
    || lp(name)
    || lp(uid)          // may be empty — see below
    || configHash       // 32 raw bytes, fixed width, last
)
```

Three properties this buys:

- **Distinct domains.** `workloadID` and `signedDigest` use different domain
  strings, so a value computed for one can never be accepted as the other.
- **Version in the domain *and* the body.** The domain string carries `v2` so a
  v1 and a v2 preimage can never collide even if someone constructs matching
  bodies; `u16be(protocolVersion)` keeps 0001's existing property that altering
  the stored version breaks the signature rather than selecting a different
  normalizer.
- **Everything a publisher must not swap independently is inside.** A
  compromised EOA cannot re-file a valid signature under another cluster,
  namespace, name, or incarnation, because all of them are in the preimage.

### Validation, not just encoding

- `clusterID` **must** be non-empty. An empty one is a configuration error at
  startup, never an empty `lp("")` in a digest.
- `uid` **may** be empty, and empty means exactly one thing: *no incarnation is
  asserted*. It is legal, it is length-prefixed like any other field so it
  cannot collide with a present UID, and it **must** change the verifier's
  result — see Decision 3. It is never a silent absence.
- No field is case-folded, trimmed, or Unicode-normalized. Kubernetes already
  constrains these strings; re-normalizing adds a second definition to disagree
  with.

## Decision 3 — The verifier exit-code contract

Printing a different message is not enough. `pod-verify` is meant to be run in
CI, and CI branches on exit status.

| Code | Meaning |
|---|---|
| `0` | **PASS** — signature valid, config hash matches, incarnation verified. |
| `1` | **Operational error** — RPC, kubeconfig, contract, or malformed record. Nothing was decided. |
| `2` | **FAIL** — verification completed and the answer is no: hash mismatch, bad signature, or a different UID. |
| `3` | **PARTIAL** — verification completed with a guarantee weaker than PASS. The reason is printed. |

`3` covers the two cases 0001 calls out: a manifest with no UID (incarnation not
verified), and a v1 record accepted under `--allow-v1` (weak surface). Both
completed successfully and both mean less than a `0`.

This fixes the defect the README already admits — one non-zero exit shared by
semantic failure and operational error — rather than one instance of it. The
load-bearing consequence: a `set -e` script can no longer treat "config matched
but we never checked which instance" as a pass.

Human-readable output stays as 0001 specifies:

```
CONFIG MATCH  payments/api
  incarnation: NOT VERIFIED (manifest has no Kubernetes UID)
```

## Golden vectors required before implementation

0001 requires vectors before code. Concretely, at minimum:

1. `workloadID` for a known identity tuple.
2. `signedDigest` with a UID present.
3. `signedDigest` with the UID empty — proving it is distinguishable from (2)
   rather than merely shorter.
4. **An ambiguity pair**: two different identity tuples that would collide under
   naive `/` concatenation — `{namespace: "a/b", name: "c"}` versus
   `{namespace: "a", name: "b/c"}` — asserted to produce *different* digests.
   This is the test that would have caught v1's non-injective construction, and
   it is the one that must exist before any encoder is written.
5. A v1 and a v2 digest over the same config hash, asserted unequal.

(4) is the reason this ADR exists. The others confirm the encoder; (4) confirms
the encoding.

## Consequences

- `attest.DeploymentID` is superseded, not extended. It stays for reading v1
  records under `--allow-v1`.
- `clusterID` becomes required operator configuration, and the operator must
  refuse to start without it. There is no defensible default, and inferring one
  from kubeconfig is what 0001 forbids.
- `SigningDigest`'s signature changes from `(Version, [32]byte)` to taking the
  full identity. Every caller is forced to supply it, which is the point.
- `pod-verify` gains two exit codes. Any existing caller treating non-zero as
  "failed" keeps working; callers that want the distinction now have it.
