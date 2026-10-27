# proof-of-deploy

A Kubernetes operator that observes `apps/v1` Deployments, hashes a normalized
subset of each converged Deployment's configuration, signs that hash with an AWS
KMS key, and records the signature on a public EVM testnet. A companion CLI
(`pod-verify`) independently recomputes the hash from a live cluster and checks
it against the on-chain record.

> **Status: testnet demonstration.** Not production software. Never point it at
> mainnet, and never fund the Ethereum account it uses with real value. The
> operator publishes and the verifier accepts **hash protocol v2 only**. See
> [What PASS means](#what-pass-means) for exactly what a `PASS` claims,
> [Known gaps](#known-gaps) for what is missing, and [SECURITY.md](SECURITY.md)
> before reporting anything.

---

## How it works

```
Kubernetes apiserver
  │  watch (cluster-wide; Deployments are get/list/watch only)
  ▼
DeploymentReconciler.Reconcile
  │  attest only once the rollout has converged
  ▼
attest.NormalizeV2  →  configHash = SHA-256(canonical JSON)
  │  workload identity = (CLUSTER_ID, apps/v1, Deployment, namespace, name)
  ▼
PublisherV2.Enqueue       (in-memory; reconcile returns immediately)
  │
  ├─ read the chain first: already published and signature verifies? → done
  ├─ AWS KMS sign the v2 envelope digest
  │     SHA-256(domain ‖ version ‖ identity ‖ UID ‖ configHash), MessageType=DIGEST
  └─ prepare once → send → wait for the receipt (EOA pays testnet gas)
       ▼
AttestationRegistryV2.latest[workloadId]
       │  configHash, incarnation, signature, signer fingerprint, hash version
       ▼
pod-verify  →  PASS (exit 0) / FAIL (exit 1) / could not decide (exit 2)
```

The reconciler never blocks on signing or chain I/O. It has read-only access to
Deployments and cannot mutate, delay, or back-pressure any of them. That is the
project's one hard invariant. (Leader election does write a Lease and Events in
the operator's own namespace.)

Startup refuses to run unless the RPC reports the configured chain id, the
address holds exactly the expected registry bytecode, the registry's publisher
is the account the operator holds the key for, and the KMS key is a P-256
signing key.

`internal/attest` is the single source of truth for normalization, hashing, and
verification. Both the operator and the CLI import it. Forking that logic breaks
the protocol.

---

## What PASS means

In one sentence: **the selected configuration fields of the live Deployment
match a signed observation of the same Deployment incarnation.**

Concretely, a `PASS` from `pod-verify` asserts:

1. The Deployment read from the apiserver **right now** hashes, under protocol
   v2, to the value in the registry's latest record for this cluster ID and
   namespace/name.
2. The live object has the **same UID** as the one that was signed, so a
   deleted-and-recreated Deployment does not inherit its predecessor's record.
3. The record's signer fingerprint matches the public key **you supplied to the
   verifier**, and that key's signature over the v2 envelope (version, cluster
   ID, kind, namespace, name, UID, config hash) is valid.
4. The contract address runs the expected registry bytecode, on an RPC that
   reports the configured chain id.

A `FAIL` means "not currently attested". That includes tampering, and also a
legitimate change whose rollout has not converged or whose transaction has not
mined yet.

### What PASS does **not** mean

- It does not prove the selected fields are everything that matters. **Literal
  environment variable values are not hashed**, and Kubernetes expands `$(VAR)`
  references into `command` and `args`, so changing a literal value can change
  the program that runs without changing the hash. The contents of referenced
  ConfigMaps and Secrets are not hashed either.
- It does not prove the running containers execute the image bytes the
  Deployment names. `image` is hashed as a **string**, not a resolved digest —
  `repo/app:latest` can point at different bytes tomorrow with no hash change.
- It does not prove the apiserver's view matches what the nodes actually run,
  or what mutating admission webhooks added to the Pods.
- It does not prove the cluster, kubelet, registry, or operator was honest when
  the attestation was produced.
- It does not prove KMS only ever signed authorized states.
- It carries no freshness or ordering bound. The verifier does not check how old
  the record is, and whoever holds the publisher account can re-post an older,
  validly signed record.
- The record is accepted once mined. There is no confirmation depth, so a reorg
  can still remove it.

---

## What is hashed (protocol v2)

v2 answers *"does this workload execute, and is it permitted to do, what was
attested?"* for the fields it covers. A field is in scope when it changes what a
converged Pod can do (code, arguments, credentials, isolation, resource access,
name resolution) or where it may be placed. The full reasoning is in
`docs/adr/0001-hash-protocol-v2.md`; the code is `internal/attest/normalize_v2.go`.

**Hashed**, for both `containers` and `initContainers`, in declared order:
name, image (as a string), command, args, workingDir, env var **names** and
their `valueFrom` sources, `envFrom` sources, ports, imagePullPolicy, resources,
volumeMounts, volumeDevices, securityContext, probes, lifecycle hooks, and the
container-level restartPolicy that makes an init container a sidecar.

At pod level: serviceAccountName, automountServiceAccountToken,
imagePullSecrets, hostNetwork/hostPID/hostIPC/hostUsers, runtimeClassName, pod
securityContext, shareProcessNamespace, volumes, resourceClaims, hostAliases,
DNS policy and config, hostname/subdomain, enableServiceLinks, and placement
(nodeSelector, nodeName, schedulerName, affinity, tolerations, topology spread,
priority class, preemption policy, scheduling gates, OS). Plus namespace, name,
Deployment labels, selector and pod template labels.

`TestV2SurfaceAccountsForEveryField` fails when an upstream `PodSpec` or
`Container` field is neither hashed nor excluded with a stated reason.

**Not hashed, by decision:**
- `replicas`, `strategy`, `paused`, `minReadySeconds`,
  `progressDeadlineSeconds` — delivery and scale, not capability.
- All annotations, all of `status`, and object metadata such as `uid` (the UID
  is bound separately, in the signed envelope).
- **Literal environment variable values**, so a value pasted inline never
  reaches a public chain. This is a real gap, not just hygiene: see
  [What PASS does not mean](#what-pass-does-not-mean).
- The contents of referenced ConfigMaps and Secrets, and the bytes behind an
  image tag.

### Historical: the v1 surface

v1 hashed only namespace, name, labels, replicas, selector, pod template labels,
and per container the name, image string, env var names and resources. A
workload made privileged, run as root with `hostPID` and the host filesystem
mounted, under a different ServiceAccount and command, hashed **identically**
and verified as `PASS`. `config/samples/demo-deployment-tampered.yaml` is that
workload. It now **fails** under v2. v1 is retired: nothing publishes it, and
`pod-verify` refuses it. Its normalizer and golden vectors are kept only to pin
that weakness (`TestV1WeaknessIsPinned`, `TestV2DetectsTheTamperedWorkload`).

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
| Any third party on the testnet | nothing in `latest` | `onlyPublisher`; the KMS signature | can read metadata and dictionary-attack workload IDs |
| Compromised RPC provider | `getLatest` responses; whether a publish appears to land | a valid signature, if your key is trusted out of band | can serve a stale but validly-signed attestation, or lie about chain id and code; finality is not checked |
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
| Operator restart | Publisher state is in memory and is lost. On restart the informer relists and every converged Deployment is re-enqueued; the publisher reads the chain first and does not republish a record that already matches and verifies. A transaction still pending at restart is forgotten, so it may be published a second time (same content, extra gas). |
| Two replicas, `--leader-elect` | Only the leader publishes. This is what `config/manager/manager.yaml` sets. |
| Two replicas, no leader election | Both observe, sign, and publish: duplicate gas and nonce contention. The binary defaults to `--leader-elect=false`; safety depends on the entry point. |
| KMS throttled or IAM denied | Retried with 1s–5m backoff, indefinitely. **Liveness and readiness stay green.** A permanently broken attestor looks healthy. |
| RPC down / tx not mined | A publication counts only once its receipt is mined. A send whose outcome is unknown keeps the same signed transaction and resends those exact bytes; a reverted one is rebuilt. Known gap: if another transaction takes the prepared transaction's nonce, that attempt is retried until restart or until the Deployment changes. There is no fee bumping and no confirmation depth. |
| Deployment deleted | No tombstone is written. The on-chain `latest` record persists forever. |
| Deployment recreated, same namespace/name | The new object has a new UID, so the old record no longer matches: `pod-verify` reports an incarnation-mismatch `FAIL` until the new incarnation is attested. |
| Config changed but hash-stable | Changing a literal env value (including one expanded into `command`/`args` via `$(VAR)`), the contents of a referenced ConfigMap or Secret, or what an image tag points at leaves the hash unchanged. `PASS` persists. See [What is hashed](#what-is-hashed-protocol-v2). |
| Secret value rotated | The hash does not change (values are never read). Changing *which* Secret a variable or `envFrom` points at does change it. |
| Image tag moved | Undetectable. The hash covers the tag string, not the digest. |
| Publisher EOA lost | The registry becomes permanently unwritable. No recovery path. |
| Operator attests itself | The watch is cluster-wide and does not exclude the operator's own namespace, so the manager's own Deployment is attested — when it runs in the cluster. |
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

The version is also bound into the signed envelope, so altering the stored
version breaks signature verification rather than silently selecting the wrong
normalizer.

`pod-verify` **refuses** versions it does not implement. It never tries each in
turn: falling back would let anyone able to write on-chain steer a verifier onto
a weaker hash surface by relabelling a record.

| Version | Surface | Status |
|---|---|---|
| `v1` | Narrow — see [Historical: the v1 surface](#historical-the-v1-surface). | **retired**: not published, refused by `pod-verify` |
| `v2` | Execution and privilege: containers **and init containers**, command/args, env sources, volumes and mounts, security contexts, service account, image pull secrets, host namespaces, runtime class and placement. | what the operator publishes and `pod-verify` accepts |

v2 answers *"does this workload execute, and is it permitted to do, what was
attested?"* — not *"is this Deployment identical in every declared field"*. It
deliberately does **not** attest capacity, cost, availability or scale;
`replicas` is excluded, because scaling changes no Pod's privileges while an HPA
would churn it on every stabilization.

The benign and tampered demo workloads hash identically under v1 and
**differently under v2**, which is the whole point of the change.

See `docs/adr/0001-hash-protocol-v2.md` and `docs/adr/0002-v2-encoding-and-verifier-contract.md`.

## Golden vectors

`internal/attest/testdata` pins the wire format. For each fixture there is the
input Deployment, the exact canonical JSON bytes and the config hash, under v2
(`canonical_v2.json`, `hashes_v2.txt`) and, as history, under v1. The v2
identity encoding, incarnation, signing preimage and signing digest are pinned
in `testdata/_envelope_v2/reference.txt`, and re-derived in CI by
`reference.py`, an independent implementation written from the documented
layout rather than from the Go code.

A diff in any golden file is a protocol change. Regenerate deliberately:

```sh
go test ./internal/attest -run 'TestGolden|TestV2GoldenVectors|TestEnvelopeGoldenVectors' -update
```

The benign/tampered pair hashes alike under v1 (`TestV1WeaknessIsPinned`) and
differently under v2 (`TestV2DetectsTheTamperedWorkload`).

Writing the v1 fixtures surfaced two determinism defects, both since fixed:
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
refactor. Any such change to `internal/attest/types_v2.go` needs a new hash version.

Determinism currently rests on struct declaration order, `encoding/json`'s
documented sorting of map keys, and, under v2, declared list order as the apiserver returns it.
Quantities inside resources are canonicalized by value; quantities nested in
embedded upstream types (for example an `emptyDir` size limit) use
`resource.Quantity.String()`. That last one is the least
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
| `internal/publisher` | off-reconcile sign-and-publish state machine (`PublisherV2`) |
| `internal/signer` | AWS KMS signing |
| `internal/chain` | v2 registry client (prepare/send/wait) and startup validation |
| `cmd` | the operator (`manager`) |
| `cmd/verify` | the `pod-verify` CLI — deliberately not shipped in the operator image |
| `contracts` | `AttestationRegistryV2.sol` and its Hardhat tests |

## Running it locally

`docs/local-demo.md` walks a clean checkout through to a receipt-confirmed
`PASS` with no AWS account, no testnet and no cost: LocalStack stands in for KMS
and a Hardhat node for the chain, neither of which needs a code change. It then
changes the image, applies the privileged "tampered" workload, and recreates the
Deployment; each one turns the result into `FAIL`. It is a manual runbook for
now; there is no `make demo` yet.

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
| `CONTRACT_ADDRESS` | yes | deployed `AttestationRegistryV2` |
| `CLUSTER_ID` | yes | stable identity of this cluster; part of every workload ID. Choose once, never change, never derive from the kubeconfig context. `pod-verify --cluster-id` must use the same value. |
| `ETH_PRIVATE_KEY` | yes | throwaway testnet gas key; must be the account that deployed the contract |
| `CHAIN_ID` | no | defaults to `84532` (Base Sepolia). An unparseable value silently falls back to the default. |

AWS credentials should come from IRSA or an instance profile, never a static
secret in the manifest. `config/manager/manager.yaml` expects a Secret named
`proof-of-deploy-config`, which is **not** in this repository and must be created
out of band.

---

## Known gaps

Verify against the code before relying on this list.

- **Not shown end to end in CI.** Every layer is tested on its own, including
  the chain client against a real Hardhat node, but nothing runs operator, KMS,
  chain and verifier together automatically. The local path is a manual
  runbook.
- **Literal env values are not hashed** (see
  [What PASS does not mean](#what-pass-does-not-mean)).
- **No freshness or ordering.** Whoever holds the publisher account can re-post
  an older, validly signed record.
- **Stuck transactions.** A prepared transaction whose nonce is taken by another
  is retried until restart; there is no fee bumping and no confirmation depth.
- **Pending transactions do not survive a restart** and may be published twice.
- **A failing pipeline looks healthy.** Readiness is `healthz.Ping`, and there
  are no metrics for pending work, signing or publication.
- **Every Deployment in the cluster is attested**, including the operator's own
  when it runs in-cluster. There is no opt-in or namespace selection.
- **The KMS key cannot be rotated** without every existing record failing
  verification; the verifier accepts one key.
- `image` is a tag string, not a resolved digest, and the verifier does not
  warn about mutable tags yet (ADR 0001, Decision 4).
- No manifest mode, and no PARTIAL result (ADR 0002, Decision 3).
- Hardhat falls back to a live public RPC when `RPC_URL` is unset.

`docs/adr/0001-hash-protocol-v2.md` and `docs/adr/0002-v2-encoding-and-verifier-contract.md`
record the protocol design. Parts of ADR 0002 were changed during
implementation; the code is authoritative where they differ.
