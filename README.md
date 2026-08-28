# proof-of-deploy

A Kubernetes operator that observes `apps/v1` Deployments, hashes a normalized
subset of each converged Deployment's configuration, signs that hash with an AWS
KMS key, and records the signature on a public EVM testnet. A companion CLI
(`pod-verify`) independently recomputes the hash from a live cluster and checks
it against the on-chain record.

> **Status: testnet demonstration.** Not production software. Never point it at
> mainnet, and never fund the Ethereum account it uses with real value. See
> [Known gaps](#known-gaps) for what is missing.

---

## How it works

```
Kubernetes apiserver
  │  watch (cluster-wide, get/list/watch only — no write verbs anywhere)
  ▼
DeploymentReconciler.Reconcile
  │  attest only once the rollout has converged
  ▼
attest.Normalize  →  attest.ConfigHash = SHA-256(canonical JSON)
  │
  ▼
Publisher.Enqueue         (in-memory queue; reconcile returns immediately)
  │
  ├─ AWS KMS SignDigest   (ECC_NIST_P256 / ECDSA_SHA_256 / MessageType=DIGEST)
  └─ chain.PublishAttestation   (EOA pays testnet gas)
       ▼
AttestationRegistry.latest[deploymentId]
       │  configHash, DER signature, signer fingerprint, block timestamp
       ▼
pod-verify  →  PASS / FAIL
```

The reconciler never blocks on signing or chain I/O. It holds a read-only
ClusterRole and cannot mutate, delay, or back-pressure any Deployment. That is
the project's one hard invariant.

`internal/attest` is the single source of truth for normalization, hashing, and
verification. Both the operator and the CLI import it. Forking that logic breaks
the protocol.

---

## What PASS means

A `PASS` from `pod-verify` asserts exactly three things:

1. The Deployment read from the apiserver **right now** normalizes and hashes to
   the same value recorded on-chain.
2. The signer fingerprint on-chain matches SHA-256 of the DER public key **you
   supplied to the verifier**.
3. That key's ECDSA signature over the config hash is valid.

### What PASS does **not** mean

- It does not prove the running containers execute the image bytes the
  Deployment names. `image` is hashed as a **string**, not a resolved digest —
  `repo/app:latest` can point at different bytes tomorrow with no hash change.
- It does not prove the apiserver's view matches what the nodes actually run.
- It does not prove the cluster, kubelet, registry, or operator was honest when
  the attestation was produced.
- It does not prove KMS only ever signed authorized states.
- It does not prove the excluded fields match. **Two workloads with materially
  different behavior and privileges can share a config hash** — see the next
  section.
- It carries no freshness bound. The verifier does not check how old the
  attestation is.

---

## What fields are excluded and why

This is the section the code has been pointing at, and it is the most important
limitation in the project.

### What IS hashed

| Field | Notes |
|---|---|
| `metadata.namespace`, `metadata.name` | also the identity |
| `metadata.labels` | minus the generated denylist below |
| `spec.replicas` | `nil` normalized to `1` |
| `spec.selector` | `matchLabels` and sorted `matchExpressions` |
| `spec.template.metadata.labels` | minus the generated denylist |
| container `name`, `image` | image as a **string**, not a digest |
| container env **names** | values are never read |
| container `resources.requests` / `.limits` | canonical `Quantity` strings |

Only `spec.template.spec.containers` is read. Labels excluded as
controller-generated: `pod-template-hash`, `controller-revision-hash`,
`pod-template-generation`, `statefulset.kubernetes.io/pod-name`,
`apps.kubernetes.io/pod-index`, `batch.kubernetes.io/job-completion-index`.

### What is NOT hashed

Excluded for good reasons — annotations are rewritten constantly by `kubectl
apply`, Helm, cert-manager and mesh injectors; `status` is observed output, not
declared intent; env **values** are excluded so a Secret can never leak into the
hash, the logs, or a public chain:

- all annotations; all of `status`; `uid`, `resourceVersion`, `generation`,
  timestamps, and all other object metadata
- environment variable **values**

Excluded with **no principled justification — these are gaps, not decisions**:

- `initContainers` (including a malicious init step)
- `command` and `args` — *a different program entirely, from the same image*
- `securityContext` at pod and container level: `privileged`, `capabilities`,
  `runAsUser`, `allowPrivilegeEscalation`
- `serviceAccountName` and mounted tokens
- `volumes` and `volumeMounts`, including `hostPath`, Secrets, ConfigMaps
- `envFrom` and `valueFrom` — the *source* of a variable, not just its name
- `hostNetwork`, `hostPID`, `hostIPC`
- `ports`, `workingDir`, `imagePullPolicy`
- probes and lifecycle hooks
- scheduling: `nodeSelector`, `affinity`, `tolerations`, `runtimeClassName`
- ephemeral containers
- Deployment `strategy`, `paused`, `minReadySeconds`, `progressDeadlineSeconds`

**Consequence.** An attacker who can change a Deployment's `command`, mount a
`hostPath`, swap the `serviceAccountName`, add a privileged `initContainer`, or
set `privileged: true` produces a workload that is materially more dangerous and
**hashes identically**. `pod-verify` will print `PASS`.

The current hash therefore represents a narrow slice of declarative identity —
roughly "the same named containers, from the same image tags, with the same env
var names and resource envelope". It does not represent what the workload does
or what it is allowed to do. Widening this surface is the single highest-value
change to the protocol, and it must be done as an explicit versioned change (see
[Hash versioning](#hash-versioning)).

---

## Trust boundary

**The claim this system can support:** *this is the Deployment object as the
apiserver served it, hashed by a subset of its fields, signed by a specific KMS
key, and recorded by a specific authorized EOA.*

**What it cannot support:** any claim about the bytes actually executing, node
integrity, the supply chain, or the honesty of the cluster.

| Actor | Can forge | Cannot forge without another key | Residual risk |
|---|---|---|---|
| Compromised apiserver / cluster admin | any observed object and its apparent convergence | the KMS signature; the on-chain write | the operator faithfully signs a false observation; there is no independent source of truth |
| Compromised node / kubelet | what actually runs — binaries, mounts, traffic | the object the apiserver serves | `PASS` coexists with malicious execution |
| Compromised operator process | arbitrary hashes submitted for signing and publication | extraction of the KMS private key | with `kms:Sign` **and** `ETH_PRIVATE_KEY` it can publish a cryptographically valid attestation of anything |
| Holder of `kms:Sign` | valid P-256 signatures over invented hashes | the on-chain write | can pre-sign; total compromise when combined with the EOA |
| Holder of `ETH_PRIVATE_KEY` | overwrite `latest` with arbitrary bytes | a valid new KMS signature | denial of service and censorship by overwrite; contract is unrecoverable if the key is lost |
| Any third party on the testnet | nothing in `latest` | `onlyPublisher`; the KMS signature | can read metadata and dictionary-attack Deployment IDs |
| Compromised RPC provider | `getLatest` responses; whether a publish appears to land | a valid signature, if your key is trusted out of band | can serve a stale but validly-signed attestation; chain ID and finality are not checked |
| Verifier with the wrong public key | its own root of trust | — | if the key and the RPC endpoint come from the same hostile channel, verification is circular |

Two consequences worth stating plainly:

- **A signature proves control of signing capability, not honesty of origin.**
- **The contract proves an authorized EOA wrote a record, not that anything was
  verified.** It does not check the KMS signature; it does not know the trusted
  public key.

The verifier must obtain the expected public key through a channel it trusts
independently of the chain and the cluster. The on-chain fingerprint confirms
*which* key signed; it cannot tell you that key deserved trust.

### The two keys

They are unrelated and must never be conflated:

| | Purpose | Custody |
|---|---|---|
| **KMS `ECC_NIST_P256` key** | signs the config hash — this is the attestation | private key never leaves KMS |
| **`ETH_PRIVATE_KEY`** | signs transactions and pays gas | throwaway testnet EOA; **not** an attestation key |

The EOA that deploys the contract becomes its **immutable** `publisher`. Rotating
it is impossible: losing or compromising that key means deploying a new contract
and redistributing its address to every consumer.

---

## Failure modes

| Situation | Behavior |
|---|---|
| Rollout in progress | Not attested until converged. The operator never slows the rollout. If it never converges, there is no attestation and no specific alarm. |
| Operator restart with a pending queue | The queue is in memory and is lost. On restart the informer relists and the empty dedup cache re-enqueues converged Deployments — eventual recovery by accident, not durability. |
| Two replicas, `--leader-elect` | Only the leader publishes. This is what `config/manager/manager.yaml` sets. |
| Two replicas, no leader election | Both observe, sign, and publish: duplicate gas and nonce contention. The binary defaults to `--leader-elect=false`; safety depends on the entry point. |
| KMS throttled or IAM denied | Retried with 1s–5m backoff, indefinitely. **Liveness and readiness stay green.** A permanently broken attestor looks healthy. |
| RPC down / tx never mined | `PublishAttestation` returns on *send*, not on receipt. A dropped, replaced, or reverted transaction is recorded as success and never retried. |
| Deployment deleted | No tombstone is written. The on-chain `latest` record persists forever. |
| Deployment recreated, same namespace/name | The dedup entry is dropped on the observed delete, so the new incarnation is attested. **Residual window:** `DeploymentID` is `SHA-256("namespace/name")` with no UID, so between the recreate and the new transaction being mined, `pod-verify` matches the new object against the *previous* incarnation's record and returns `PASS`. Closing this requires a protocol change. |
| Config changed but hash-stable | `command`, `args`, `serviceAccountName`, volumes, security contexts — all change behavior without changing the hash. `PASS` persists. See [excluded fields](#what-fields-are-excluded-and-why). |
| Secret value rotated | The hash does not change (values are never read). Neither does changing which Secret an `envFrom` points at. |
| Image tag moved | Undetectable. The hash covers the tag string, not the digest. |
| Publisher EOA lost | The registry becomes permanently unwritable. No recovery path. |
| Operator attests itself | The watch is cluster-wide and does not exclude the operator's own namespace, so the manager's own Deployment is attested — including its mutable `:latest` tag. |
| Large cluster (thousands of Deployments) | Every converged Deployment costs one KMS call and one transaction. There is no batching, allowlist, quota, or backlog metric. A restart can re-enqueue everything. |

---

## Hash protocol versions

Every attestation records which hash protocol produced it. The version is stored
**on-chain**, next to the config hash, because a verifier recomputes the hash
from the live Deployment and therefore has to know which normalizer to run
before it can produce any bytes to compare. A version living only inside the
hashed payload would be unreachable at exactly the moment it is needed, and
inferring it from the payload's shape would misverify as soon as two versions
became shape-compatible.

The version is also bound into the signed digest
(`SHA-256(domain || version || configHash)`), so altering the stored version
breaks signature verification rather than silently selecting the wrong
normalizer.

`pod-verify` **refuses** versions it does not implement. It never tries each in
turn: falling back would let anyone able to write on-chain steer a verifier onto
a weaker hash surface by relabelling a record.

| Version | Surface |
|---|---|
| `v1` | current. Narrow — see [What fields are excluded and why](#what-fields-are-excluded-and-why). Every `v1` PASS prints a warning saying so. |

See `docs/adr/0001-hash-protocol-v2.md` for the proposed v2.

## Golden vectors

`internal/attest/testdata` freezes the v1 wire format: for each fixture, the
input Deployment, the exact canonical JSON bytes, the config hash and the
deployment ID. Each fixture is self-checking — the test asserts that the stored
hash really is SHA-256 of the stored JSON — and a fixed test key plus a
precomputed signature pins the signing rule: the signature is taken over the
version-bound digest (`SHA-256(domain || version || configHash)`) and over
nothing else. Tests assert it verifies over neither the bare config hash nor a
different protocol version.

A diff in any golden file is a protocol change. Regenerate deliberately:

```sh
go test ./internal/attest -run TestGolden -update
```

One test asserts behaviour that is **wrong on purpose**: the benign/tampered
pair that hashes alike. It is written to fail once the hash surface is widened,
so closing that hole has to be a conscious, versioned decision rather than a
silent one.

Writing these fixtures surfaced two determinism defects, both since fixed:
`matchExpressions` sorted with no tiebreak on `values`, so declaration order
leaked into the hash; and quantities were canonicalized by
`resource.Quantity`'s format rather than its value, so `1Gi` and `1073741824`
hashed differently despite being the same number of bytes. Both produced the
mirror image of the weakness above — a false FAIL on a change that means
nothing. They are now regression-tested by
`TestSelectorRequirementOrderIsDeterministic` and
`TestQuantityCanonicalizationIsByValue`.

## Hash versioning

The JSON field order, the JSON tags, and the canonical encoding in
`internal/attest` are a **wire format**. Changing any of them changes every hash
this project has ever produced and silently invalidates every existing
attestation.

Specifically: swapping `json.Marshal` for `MarshalIndent`, reordering a struct
field, renaming a tag, or adding a field is a protocol change, not a
refactor. Before modifying `internal/attest/types.go`, an explicit hash version
must exist so old and new attestations can be told apart.

Determinism currently rests on struct declaration order, `encoding/json`'s
documented sorting of map keys, explicit sorting of every slice in
`normalize.go`, and `resource.Quantity.String()`. That last one is the least
guarded — its canonical form is decided by an upstream Kubernetes library, not by
this repository. **Golden vectors are the real defense here**; the toolchain pin
in `go.mod` is a precaution, not a guarantee. Both now exist — see
[Golden vectors](#golden-vectors) — though the vectors run only on the pinned Go
version, not across every version the project claims to support.

---

## Repository layout

| Path | Purpose |
|---|---|
| `internal/attest` | normalization, hashing, signature verification — the protocol |
| `internal/controller` | the passive Deployment watcher |
| `internal/publisher` | off-reconcile sign-and-publish queue |
| `internal/signer` | AWS KMS signing |
| `internal/chain` | typed wrapper over the registry contract |
| `cmd` | the operator (`manager`) |
| `cmd/verify` | the `pod-verify` CLI — deliberately not shipped in the operator image |
| `contracts` | `AttestationRegistry.sol` and its Hardhat tests |

## Running it locally

`docs/local-demo.md` walks a clean checkout through to a receipt-confirmed
`PASS` with no AWS account, no testnet and no cost: LocalStack stands in for KMS
and a Hardhat node for the chain, neither of which needs a code change. It ends
with two deliberate changes — one the hash detects, and one it does not.

## Building

```sh
make fmt-check   # fails on a formatting difference; never rewrites sources
make vet
make build       # bin/manager and bin/pod-verify
make test        # all Go unit tests, no cluster required
make contracts-test
```

`make fmt` is the only target that modifies the tree, and nothing depends on it.

## Configuration

The operator reads (flag or environment):

| Variable | Required | Notes |
|---|---|---|
| `KMS_KEY_ID` | yes | key id, ARN, or alias; spec `ECC_NIST_P256`, usage `SIGN_VERIFY` |
| `ETH_RPC_URL` | yes | testnet endpoint. **Never mainnet.** |
| `CONTRACT_ADDRESS` | yes | deployed `AttestationRegistry` |
| `ETH_PRIVATE_KEY` | yes | throwaway testnet gas key; must be the account that deployed the contract |
| `CHAIN_ID` | no | defaults to `84532` (Base Sepolia). An unparseable value silently falls back to the default. |

AWS credentials should come from IRSA or an instance profile, never a static
secret in the manifest. `config/manager/manager.yaml` expects a Secret named
`proof-of-deploy-config`, which is **not** in this repository and must be created
out of band.

---

## Known gaps

Honest inventory of what is missing, roughly in priority order.

**Protocol**
- The hash surface is too narrow to support a strong "proof of deploy" claim.
- **There is no cluster identity.** `DeploymentID` is
  `SHA-256("namespace/name")`, so `payments/api` in two different clusters
  occupies the same on-chain slot and each overwrites the other. `pod-verify`
  prints the cluster it read, but that string is local and is bound to nothing
  in the record.
- `DeploymentID` carries no incarnation, so a recreated Deployment can match its
  predecessor's record.
- `image` is a tag string, not a resolved digest.

**Correctness**
- `PublishAttestation` treats *sent* as *published*: no receipt, no finality, no
  reorg handling, no nonce management.
- `internal/chain` validates nothing about the endpoint it talks to — not the
  chain ID, not the contract's bytecode, not that `publisher()` matches the
  configured EOA. A malformed address is silently accepted.
- `internal/signer` validates `KeyUsage` but not `KeySpec`, so a non-P-256 key
  fails late instead of at startup. `PublicKeyDER()` returns its internal slice
  uncopied.
- `Selector.MatchLabels` is not filtered through the generated-label denylist,
  while pod template labels are.
- Readiness is `healthz.Ping`: a permanently failing pipeline reports Ready.
  There are no metrics for queue depth, signing, or publication.
- `pod-verify` exits `1` for both a semantic FAIL and an operational error, and
  prints a failure to stdout and stderr both.
- Hardhat falls back to a live public RPC when `RPC_URL` is unset.

**Testing and tooling**
- No tests for the publisher, the KMS signer, or the verify CLI. The chain
  client is covered only by the ABI drift check, not by encode/decode tests.
- The local end-to-end path is documented and has been executed (see
  `docs/local-demo.md`), but nothing runs it automatically: there is no e2e job
  in CI, so it can rot silently.

**Before this is more than a demo**, at minimum: a defensible hash surface,
cluster-aware identity, delivery reconciled through receipt and finality,
documented key rotation, unit and end-to-end tests, observability that notices a
dead attestor, explicit workload selection, and a published threat model. The
protocol is versioned and the ABI is automatically verified; the rest is not
done.

`docs/adr/0001-hash-protocol-v2.md` records the accepted design for closing the
protocol gaps.
