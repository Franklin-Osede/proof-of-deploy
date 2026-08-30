# Security policy

## Scope and status

This is an **experimental, testnet-only** demonstration project. It is not a
production attestation system, it has not been audited, and it must never be
pointed at mainnet or used with real funds.

The Ethereum key it uses (`ETH_PRIVATE_KEY`) pays gas and is expected to be a
disposable testnet wallet. It is **not** an attestation key: attestations are
signed inside AWS KMS and that private key never leaves KMS.

## Already known — please do not report these

These are documented design limitations, not undisclosed vulnerabilities:

- **The v1 hash surface does not cover privilege.** A workload can be made
  privileged, run as root, given host namespaces and the host filesystem, and
  handed a different ServiceAccount while producing an identical hash and a
  `PASS`. This is demonstrated deliberately in
  `config/samples/demo-deployment-tampered.yaml` and reproduced in
  `docs/local-demo.md`. Protocol v2 addresses it and is not yet wired to the
  operator.
- **No cluster identity.** `DeploymentID` is `SHA-256("namespace/name")`, so the
  same workload name in two clusters sharing a registry collides.
- **A sent transaction is treated as published.** No receipt, no finality, no
  reorg handling.
- **The operator attests every Deployment in the cluster**, including its own.
- `image` is hashed as a string, not a resolved digest, so a moved tag changes
  the running bytes without changing the hash.

The `Known gaps` section of the README is the full inventory.

## Reporting something else

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). That keeps the report private until
there is something to disclose.

Please include what you observed, how to reproduce it, and which commit you
were on. There is no bounty and no formal response SLA — this is a personal
research project.

## What would count

Something that breaks a claim the project actually makes: a way to make
`pod-verify` report `PASS` for a Deployment whose attested fields differ from
the signed record, a flaw in the canonical encoding that lets two distinct
inputs collide, or a way to forge a valid signature or on-chain record without
the KMS key or the publisher account.
