# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 and makes no compatibility promises.

## [Unreleased]

Hash protocol v2 replaces v1 everywhere. Existing v1 attestations and the v1
contract are not readable by this version.

### Changed
- The operator publishes, and `pod-verify` accepts, **hash protocol v2 only**.
  v2 covers execution and privilege (command, args, init containers, security
  contexts, host namespaces, volumes, ServiceAccount, placement), binds the
  cluster identity and the Deployment's UID into the signed envelope, and is
  recorded in the new `AttestationRegistryV2` contract.
- `CLUSTER_ID` (`--cluster-id`) is required by both the operator and
  `pod-verify`.
- `pod-verify` exit codes: `0` PASS, `1` FAIL, `2` could not decide. A
  recreated Deployment with the same spec now FAILs as an incarnation mismatch.
- A publication counts only once its receipt is mined. A send whose outcome is
  unknown resends the same signed transaction instead of preparing a new one,
  and a superseded revision is abandoned before it is sent.

### Added
- Startup validation. The operator refuses to run unless the RPC reports the
  configured chain id, the address holds the expected registry bytecode, the
  registry's publisher is the operator's account, and the KMS key is a P-256
  signing key. `pod-verify` checks the chain id and the bytecode.
- The publisher checks the on-chain signature before treating a record as
  published.
- `make demo`: a one-command run on throwaway local infrastructure (kind,
  LocalStack for KMS, a Hardhat node) that asserts PASS, then FAIL after a
  privilege escalation with the same image, then PASS after the revert. It runs
  as a CI job.
- Golden vectors for the v2 identity, incarnation and signing digest, checked
  in CI against an independent Python implementation.

### Removed
- The v1 publishing and verification path, the v1 contract, and
  `attest.DeploymentID`. The v1 normalizer and golden vectors remain only to pin
  the weakness that motivated v2.

### Fixed
- A rollback to the last published state was dropped as already published,
  even while a newer revision was desired. If the newer revision's transaction
  has already mined when the rollback is processed, the rollback is now
  republished.
- Rolling back while the newer revision's transaction is still pending no
  longer leaves the newer revision on chain. The publisher keeps every sent
  transaction whose outcome it has not observed, including superseded ones, and
  re-checks them through its own rate-limited retry, without waiting for
  another reconcile, until each one's receipt reports mined or reverted. When
  one lands it reads the chain again and republishes the current revision if
  needed. A revision is never prepared again while an earlier transaction for
  it is unresolved; that transaction is resent instead. No nonce ordering is
  assumed. Covered by `TestRollbackWhileTheNewRevisionIsPending`,
  `TestRollbackRecoversWithoutFurtherEnqueue`, `TestRollbackFlapPublishesOnce`
  and `TestRollbackWithUnresolvedTxDoesNotRepublish`.
- A rollback could stall forever when resending the earlier, still unresolved
  transaction for the same revision failed with "nothing was sent" (for
  example because it had already mined). The publisher returned before reading
  that transaction's receipt, on every pass. A send error now aborts the pass
  only for a transaction's first send; for one already sent, the error is
  logged and its receipt is read as usual, so it settles and recovery
  continues without another reconcile. Covered by
  `TestResendFaultStillReadsTheReceipt`.

### Known limitations
- `pod-verify` checks the Deployment's declared configuration. It does not
  confirm that the running Pods have converged to it: it does not read rollout
  status or `paused`.
- A prepared transaction whose nonce is taken by another transaction is resent
  while its revision is desired; once superseded it is no longer resent, but its
  receipt keeps being checked until the operator restarts. Not yet reproduced in
  a test; tracked as the next piece of work. More generally, a sent transaction
  whose outcome stays unknown, including a superseded one, is re-checked at
  capped backoff until restart and never replaced: its revision is not prepared
  again while it is unresolved.
- The list of unresolved transactions has no cap: a cap would drop a
  transaction whose outcome is unknown. It holds every sent transaction still
  waiting for a receipt: a slow one until it settles, and one that never settles
  (dropped from the mempool, nonce taken) until restart. Retained transactions
  are waited on again on every retry, and with the real chain adapter a pending
  one can hold the single publisher worker for up to the publish timeout.
- The publisher assumes a chain read reflects a write whose receipt was already
  returned. That holds on a single node without a chain reorganisation; a
  load-balanced RPC endpoint can serve a stale read, and a rollback decided on it
  can stay uncorrected until something triggers a fresh check, such as the next
  change to that Deployment.
- The record of unresolved transactions is held in memory only. After a
  restart during a rollback, a superseded transaction that mines later is not
  corrected until the Deployment changes again or the operator restarts.
- Literal environment variable values, referenced ConfigMap and Secret
  contents, and the bytes behind an image tag are not hashed. See the README.

## [v0.1.0-experimental] — 2026-08-31

First tagged release. **Experimental. Testnet only. Not a production
attestation system.**

### What this release is

A reproducible demonstration of how Kubernetes observation, AWS KMS signing and
EVM publication fit together — and, deliberately, of **why a narrow hash surface
produces misleading attestations**.

The whole path runs on a laptop with no AWS account, no testnet and no cost
(LocalStack for KMS, a Hardhat node for the chain). See `docs/local-demo.md`.

### What `PASS` means, exactly

A `PASS` from `pod-verify` asserts three things and nothing else:

1. The Deployment read from the apiserver **right now** normalizes and hashes to
   the value recorded on-chain.
2. The signer fingerprint on-chain matches SHA-256 of the DER public key **the
   verifier was given**.
3. That key's ECDSA signature over the version-bound digest is valid.

### What `PASS` does **not** mean

- It does not prove the running containers execute the bytes the image names.
  `image` is hashed as a **string**, not a resolved digest.
- It does not prove the apiserver's view matches what the nodes run.
- It does not prove the cluster, kubelet, registry or operator was honest.
- It does not prove KMS only ever signed authorized states.
- **Under `v1` it does not prove the workload is not privileged.** See below.
- It carries no freshness bound and no cluster identity.

### Known and demonstrated: the v1 hash surface is unsafe

The operator publishes protocol `v1`, whose surface covers only namespace, name,
labels, replicas, selector, pod template labels, and per container the name,
image string, env var **names** and resources.

`config/samples/demo-deployment-tampered.yaml` is byte-identical to the benign
sample in every hashed field and materially more dangerous in every other:
`privileged: true`, `runAsUser: 0`, `hostPID`, the host root filesystem mounted
at `/host`, a different ServiceAccount, a different command, and an extra init
container. **Both hash identically and both verify as `PASS`.**

This is reproduced end to end in `docs/local-demo.md` and pinned as a regression
test. Every `v1` `PASS` prints a warning saying what it does not cover.

### Added

- Protocol versioning. The version is stored on-chain and bound into the signed
  digest; `pod-verify` refuses versions it does not implement rather than
  falling back, since trying each in turn is a downgrade oracle.
- Golden vectors freezing the v1 wire format, self-checking, with a fixed test
  key pinning the signing rule.
- **Protocol v2**: `NormalizeV2` covers execution and privilege — containers and
  init containers, command/args, env sources, volumes and mounts, security
  contexts, service account, image pull secrets, host namespaces, runtime class
  and placement. The benign and tampered workloads hash **differently** under
  v2. A reflection test fails when an upstream `PodSpec` field is in neither the
  surface nor the documented exclusions.
- `WorkloadIdentityV2` and `EnvelopeV2`: cluster-aware identity with an
  injective encoding, and a signed envelope binding version, identity,
  incarnation and config hash.
- `AttestationRegistryV2`: keyed by cluster-aware identity, records the
  incarnation, and emits a self-sufficient event so a superseded attestation
  stays verifiable.
- `pod-verify --context`, and the cluster named in the `PASS` output.
- CI: formatting, tidiness, build, tests, contract tests, and a check that the
  Go ABI matches the compiled contract.
- `LICENSE`, `--version` on both binaries, a local demo runbook, and
  `docs/adr/0001-hash-protocol-v2.md`.

### Fixed

- The dedup cache outlived the Deployment it described, so a recreated workload
  was silently covered by its predecessor's on-chain record.
- The config hash was not deterministic: `matchExpressions` sorted without a
  tiebreak on values, and quantities canonicalized by format rather than value,
  so `1Gi` and `1073741824` hashed differently. Both produced false `FAIL`s.
- `make` targets rewrote tracked sources via `go fmt`.
- A clean checkout did not build: `go.sum` was absent.

### Not in this release

`v2` is implemented and verifiable but **not wired to the operator**. The
operator still publishes `v1`. Also missing: receipt confirmation (a sent
transaction is treated as published), startup validation of the RPC and
contract, explicit workload selection (the operator attests every Deployment in
the cluster, including its own), and metrics.

### Do not

Use this on mainnet, with real funds, or as evidence that a deployed workload is
safe.

[Unreleased]: https://github.com/Franklin-Osede/proof-of-deploy/compare/v0.1.0-experimental...HEAD
[v0.1.0-experimental]: https://github.com/Franklin-Osede/proof-of-deploy/releases/tag/v0.1.0-experimental
