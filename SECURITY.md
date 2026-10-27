# Security policy

## Scope and status

This is an **experimental, testnet-only** demonstration project. It is not a
production attestation system, it has not been audited, and it must never be
pointed at mainnet or used with real funds.

The Ethereum key it uses (`ETH_PRIVATE_KEY`) pays gas and is expected to be a
disposable testnet wallet. It is **not** an attestation key: attestations are
signed inside AWS KMS and that private key never leaves KMS.

The operator publishes, and `pod-verify` accepts, **hash protocol v2 only**.
v1 is retired; its normalizer is kept in the repository as a pinned example of
a weak hash surface, not as a supported path.

## Already known — please do not report these

These are documented design limitations, not undisclosed vulnerabilities:

- **Literal environment variable values are not hashed.** Kubernetes expands
  `$(VAR)` references into `command` and `args`, so changing a literal value
  can change what runs without changing the hash. Contents of referenced
  ConfigMaps and Secrets are not hashed either.
- **`image` is hashed as a string**, not a resolved digest, so a moved tag
  changes the running bytes without changing the hash.
- **No freshness or ordering.** Whoever controls the publisher account can
  re-post an older, validly signed record for the same Deployment incarnation.
- **No confirmation depth.** A record counts once its transaction is mined; a
  reorg can remove it.
- **The operator attests every Deployment in the cluster**, and a failing
  pipeline is not reflected in readiness.
- **The apiserver, nodes, admission webhooks and the operator itself are
  trusted.** A `PASS` is a statement about the object the apiserver served, not
  about what executes.

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
`pod-verify` report `PASS` when a hashed v2 field, the UID, or the workload
identity differs from the signed record; a flaw in the canonical encoding that
lets two distinct inputs collide; or a way to forge a valid signature or
on-chain record without the KMS key or the publisher account.
