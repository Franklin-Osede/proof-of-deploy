# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 and makes no compatibility promises.

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

[v0.1.0-experimental]: https://github.com/Franklin-Osede/proof-of-deploy/releases/tag/v0.1.0-experimental
