# Local demo: clean checkout to a receipt-confirmed PASS

Runs the whole pipeline on your machine with **no AWS account, no testnet, no
faucet, and no cost**. AWS KMS is replaced by LocalStack and the EVM by a local
Hardhat node. Neither substitution requires a code change: the AWS SDK honours
`AWS_ENDPOINT_URL_KMS`, and the chain client takes any JSON-RPC URL.

Base Sepolia is a later smoke test. Never mainnet, never real funds.

## Prerequisites

`docker`, `kind`, `kubectl`, `go`, `node`, and the AWS CLI (only to create the
demo KMS key).

## 1. Local KMS

The `:4` tag is the last community image; `:latest` now requires a licence.

```sh
docker run -d --name localstack-pod -p 4566:4566 -e SERVICES=kms \
  localstack/localstack:4

# LocalStack needs ~15-30s before KMS answers. Without this wait the next
# command fails with "Connection was closed before we received a valid
# response".
curl -s --retry 40 --retry-delay 3 --retry-all-errors --max-time 5 \
  http://localhost:4566/_localstack/health >/dev/null

export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export AWS_ENDPOINT_URL_KMS=http://localhost:4566

export KMS_KEY_ID=$(aws --endpoint-url=$AWS_ENDPOINT_URL_KMS kms create-key \
  --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --query 'KeyMetadata.KeyId' --output text)
```

## 2. Local chain and contract

```sh
cd contracts && npm ci
npx hardhat node &                     # chain id 31337 on :8545

# Same again: the node is not listening the instant it is backgrounded, and
# deploying too early fails with ECONNREFUSED on 127.0.0.1:8545.
curl -s --retry 30 --retry-delay 2 --retry-all-errors --max-time 5 \
  -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
  http://127.0.0.1:8545 >/dev/null

npx hardhat run scripts/deploy.js --network localhost
```

Every step from here on assumes the same shell: the exports above are carried
forward, not re-derived.

Note the printed `CONTRACT_ADDRESS`. The deployer becomes the contract's
immutable `publisher`, so the operator must use that same account as
`ETH_PRIVATE_KEY` — account #0 of the Hardhat node.

## 3. Cluster and workload

```sh
kind create cluster --config hack/kind-cluster.yaml
kubectl apply -f config/samples/demo-deployment.yaml
kubectl -n demo rollout status deploy/api
```

## 4. Run the operator

For the fully local demo, run it **outside** the cluster: it needs to reach
LocalStack and the Hardhat node on your host, which kind nodes cannot do without
extra networking.

```sh
export ETH_RPC_URL=http://127.0.0.1:8545
export CONTRACT_ADDRESS=<from step 2>
export ETH_PRIVATE_KEY=<account #0 key printed by `npx hardhat node`>
export CHAIN_ID=31337
export CLUSTER_ID=local-demo
go run ./cmd
```

Startup first logs `chain validated`: the operator has checked the chain id, that
the address runs the expected registry bytecode, and that the registry's
publisher is the account it holds the key for. Then watch for
`attestation published` with a tx hash.

The operator watches the **whole cluster**, so it will also attest `coredns` and
`local-path-provisioner`. That is current behaviour, not a bug in the demo — see
README "Failure modes".

## 5. Verify

```sh
go build -o bin/pod-verify ./cmd/verify
./bin/pod-verify verify --context kind-proof-of-deploy \
  --namespace demo --name api \
  --eth-rpc-url http://127.0.0.1:8545 \
  --contract-address <from step 2> \
  --chain-id 31337 \
  --cluster-id local-demo \
  --kms-key-id "$KMS_KEY_ID"
```

`--cluster-id` must be the value the operator was given: it is part of the
workload ID, so a different value looks up a different record.

Expected:

```
PASS  demo/api
  cluster:            kind-proof-of-deploy (https://127.0.0.1:PORT)
  cluster id:         local-demo
  uid:                <the Deployment's UID>
  hash protocol:      v2
  config hash:        <64 hex digits>
  signer fingerprint: <depends on the key you created in step 1>
  ...
```

The fingerprint is whatever LocalStack minted for you and differs every run.

Exit codes: `0` PASS, `1` FAIL, `2` the verifier could not reach an answer
(unreachable RPC, wrong contract, missing flags).

> On a machine with several clusters, pass `--context kind-proof-of-deploy`.
> Without it the CLI follows whatever context is currently active. The PASS
> output names the cluster it actually read, so check that line.

## 6. The demonstrations

Stop the operator before each one, so it does not re-attest the change you are
about to detect.

### A changed image

```sh
kubectl -n demo set image deploy/api server=registry.k8s.io/pause:3.10
# rerun pod-verify -> FAIL, config hash mismatch
```

### A privilege escalation that keeps the same image

```sh
kubectl apply -f config/samples/demo-deployment-tampered.yaml
kubectl -n demo rollout status deploy/api
# rerun pod-verify -> FAIL, config hash mismatch
```

The tampered manifest runs privileged, as root, with `hostPID`, with the host
root filesystem mounted at `/host`, under a different ServiceAccount, executing
a different command, with an extra init container -- and the same image. v1
hashed it identically to the benign one and printed `PASS`; v2 covers those
fields, so it fails. The golden vectors
`internal/attest/testdata/08-v1-weakness-benign` and `09-v1-weakness-tampered`
pin both hashes.

### Delete and recreate

```sh
kubectl apply -f config/samples/demo-deployment.yaml   # back to the benign spec
# start the operator, wait for `attestation published`, stop it again
kubectl -n demo delete deploy/api
kubectl apply -f config/samples/demo-deployment.yaml
# rerun pod-verify -> FAIL, incarnation mismatch
```

The spec is identical, so the config hash matches. The new object has a new
UID, and the record was signed for the old one.

### What v2 still does not see

Literal environment values, the contents of referenced ConfigMaps and Secrets,
what the ServiceAccount is allowed to do, and what a mutable image tag points
at. See README "What fields are excluded and why".

## Running the operator inside the cluster

Only useful once you point at endpoints reachable from inside the cluster (real
KMS, real testnet RPC), since the local demo's LocalStack and Hardhat node live
on your host.

```sh
make docker-build
kind load docker-image proof-of-deploy:latest --name proof-of-deploy
kubectl -n proof-of-deploy-system create secret generic proof-of-deploy-config \
  --from-literal=KMS_KEY_ID=... \
  --from-literal=ETH_RPC_URL=... \
  --from-literal=CONTRACT_ADDRESS=... \
  --from-literal=ETH_PRIVATE_KEY=... \
  --from-literal=CHAIN_ID=... \
  --from-literal=CLUSTER_ID=...
kubectl apply -k config/kind
```

See `config/samples/proof-of-deploy-config.example.yaml` for the Secret shape.
That file is a template of placeholders; do not apply it as-is.

## Teardown

```sh
kind delete cluster --name proof-of-deploy
docker rm -f localstack-pod
kill %1                       # the hardhat node
```
