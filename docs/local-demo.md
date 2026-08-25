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
npx hardhat run scripts/deploy.js --network localhost
```

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
go run ./cmd
```

Watch for `attestation published` with a tx hash.

The operator watches the **whole cluster**, so it will also attest `coredns` and
`local-path-provisioner`. That is current behaviour, not a bug in the demo — see
README "Failure modes".

## 5. Verify

```sh
go build -o bin/pod-verify ./cmd/verify
./bin/pod-verify verify --kubeconfig ~/.kube/config \
  --namespace demo --name api \
  --eth-rpc-url http://127.0.0.1:8545 \
  --contract-address <from step 2> \
  --kms-key-id "$KMS_KEY_ID"
```

Expected:

```
PASS  demo/api
  config hash:        ba7e7ec9...
  signer fingerprint: 73e6f050...
```

> `pod-verify` has no `--context` flag and uses your current kubeconfig context.
> On a machine with several clusters, pass `--kubeconfig` with a file scoped to
> the right cluster (`kind get kubeconfig --name proof-of-deploy > /tmp/kc`).

## 6. The two demonstrations

### A change that IS detected

```sh
kubectl -n demo set image deploy/api server=registry.k8s.io/pause:3.10
# rerun pod-verify -> FAIL, config hash mismatch
```

### A change that is NOT detected

Stop the operator first, so it does not re-attest, then:

```sh
kubectl apply -f config/samples/demo-deployment-tampered.yaml
kubectl -n demo rollout status deploy/api
# rerun pod-verify -> PASS
```

The workload is now running privileged, as root, with `hostPID`, with the host
root filesystem mounted at `/host`, under a different ServiceAccount, executing
a different command, with an extra init container — and it produces the **same
config hash** and the same `PASS`.

That is the point of the exercise. `PASS` speaks only about the fields listed in
README "What fields are excluded and why". Until the hash surface is widened
under an explicit protocol version, it is not evidence about privilege or
behaviour.

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
  --from-literal=CHAIN_ID=...
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
