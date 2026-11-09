#!/usr/bin/env bash
# One-command demonstration of the v2 protocol, end to end, on throwaway
# infrastructure: a kind cluster, a Hardhat node, and LocalStack standing in for
# AWS KMS. It runs the real operator and the real verifier, and asserts on the
# verifier's exit codes:
#
#   1. initial Deployment, operator running        -> PASS (exit 0)
#   2. operator stopped; container made privileged
#      with hostPID, same image                    -> FAIL (exit 1)
#   3. operator still stopped; change reverted on
#      the same object (same UID)                  -> PASS (exit 0)
#
# The operator stays stopped from before the change until the end, so the
# final PASS is the original record matching the restored object, not a fresh
# attestation of whatever was there.
#
# Everything it creates carries a per-run id and is removed on exit, success or
# failure. It never touches other clusters, containers or processes, and never
# writes to ~/.kube/config. Set DEMO_KEEP=1 to leave the resources up for
# inspection; the exit message says how to remove them.
#
# Used unchanged locally (`make demo`) and in CI.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Bounded waits, in seconds. Generous for a cold CI runner pulling images.
LOCALSTACK_TIMEOUT=${DEMO_LOCALSTACK_TIMEOUT:-120}
CHAIN_TIMEOUT=${DEMO_CHAIN_TIMEOUT:-60}
CLUSTER_TIMEOUT=${DEMO_CLUSTER_TIMEOUT:-180}
ROLLOUT_TIMEOUT=${DEMO_ROLLOUT_TIMEOUT:-120}
OPERATOR_START_TIMEOUT=${DEMO_OPERATOR_START_TIMEOUT:-60}
PUBLISH_TIMEOUT=${DEMO_PUBLISH_TIMEOUT:-180}

RUN_ID=$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
CLUSTER=pod-demo-$RUN_ID
KMS_CONTAINER=pod-demo-kms-$RUN_ID
CLUSTER_ID=demo-$RUN_ID
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/pod-demo-$RUN_ID.XXXXXX")
KCFG=$WORKDIR/kubeconfig

# Hardhat's account #0. A published development key: it exists only on the
# throwaway node and is never valuable anywhere.
ETH_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

MANAGER=$ROOT/bin/manager
VERIFY=$ROOT/bin/pod-verify

# Ownership flags: cleanup removes only what this run created.
KMS_CREATED=0
CLUSTER_CREATED=0
HARDHAT_PID=
OPERATOR_PID=

log()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\nDEMO FAILED: %s\n' "$*" >&2; exit 1; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# wait_until TIMEOUT DESCRIPTION CMD... polls CMD every 2s until it succeeds.
wait_until() {
  local timeout=$1 desc=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  until "$@"; do
    if ((SECONDS >= deadline)); then
      die "timed out after ${timeout}s waiting for $desc"
    fi
    sleep 2
  done
}

kc() { kubectl --kubeconfig "$KCFG" "$@"; }

dump_diagnostics() {
  printf '\n---------------- diagnostics (run %s) ----------------\n' "$RUN_ID" >&2
  if [[ -s $WORKDIR/verify.out ]]; then
    printf '\n--- last pod-verify output\n' >&2
    cat "$WORKDIR/verify.out" >&2
  fi
  if [[ -s $WORKDIR/operator.log ]]; then
    printf '\n--- operator log (last 60 lines)\n' >&2
    tail -n 60 "$WORKDIR/operator.log" >&2
  fi
  if [[ -s $WORKDIR/hardhat.log ]]; then
    printf '\n--- hardhat node log (last 30 lines)\n' >&2
    tail -n 30 "$WORKDIR/hardhat.log" >&2
  fi
  if ((KMS_CREATED)); then
    printf '\n--- localstack log (last 30 lines)\n' >&2
    docker logs --tail 30 "$KMS_CONTAINER" >&2 2>&1 || true
  fi
  if ((CLUSTER_CREATED)) && [[ -s $KCFG ]]; then
    printf '\n--- demo/api\n' >&2
    kc -n demo get deploy,rs,pods -o wide >&2 2>&1 || true
    kc -n demo describe deploy api >&2 2>&1 | tail -n 40 >&2 || true
  fi
  printf '\n-------------------------------------------------------\n' >&2
}

stop_operator() {
  [[ -n $OPERATOR_PID ]] || return 0
  if kill -0 "$OPERATOR_PID" 2>/dev/null; then
    kill -TERM "$OPERATOR_PID" 2>/dev/null || true
    local deadline=$((SECONDS + 15))
    while kill -0 "$OPERATOR_PID" 2>/dev/null && ((SECONDS < deadline)); do sleep 1; done
    kill -KILL "$OPERATOR_PID" 2>/dev/null || true
  fi
  wait "$OPERATOR_PID" 2>/dev/null || true
  OPERATOR_PID=
}

cleanup() {
  stop_operator
  if [[ ${DEMO_KEEP:-0} == 1 ]]; then
    printf '\nDEMO_KEEP=1: leaving resources up. Remove them with:\n' >&2
    [[ -n $HARDHAT_PID ]] && printf '  kill %s\n' "$HARDHAT_PID" >&2
    ((KMS_CREATED)) && printf '  docker rm -f %s\n' "$KMS_CONTAINER" >&2
    ((CLUSTER_CREATED)) && printf '  kind delete cluster --name %s\n' "$CLUSTER" >&2
    printf '  rm -rf %s\n' "$WORKDIR" >&2
    return
  fi
  if [[ -n $HARDHAT_PID ]]; then
    kill "$HARDHAT_PID" 2>/dev/null || true
    wait "$HARDHAT_PID" 2>/dev/null || true
  fi
  if ((KMS_CREATED)); then
    docker rm -f "$KMS_CONTAINER" >/dev/null 2>&1 || true
  fi
  if ((CLUSTER_CREATED)); then
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KCFG" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}

on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  if ((rc != 0)); then
    dump_diagnostics
  fi
  log "cleaning up run $RUN_ID"
  cleanup
  if ((rc == 0)); then
    printf '\nDEMO PASSED: PASS -> FAIL -> PASS, as expected.\n'
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# run_verify runs pod-verify once and sets VERIFY_RC. Output goes to
# verify.out so a failure can show the last answer.
run_verify() {
  VERIFY_RC=0
  "$VERIFY" verify \
    --kubeconfig "$KCFG" --context "kind-$CLUSTER" \
    --namespace demo --name api \
    --eth-rpc-url "$ETH_RPC_URL" \
    --contract-address "$CONTRACT_ADDRESS" \
    --chain-id 31337 \
    --cluster-id "$CLUSTER_ID" \
    --public-key "$WORKDIR/signer.der" >"$WORKDIR/verify.out" 2>&1 || VERIFY_RC=$?
}

# expect_verify WANT_RC [REQUIRED_TEXT]
expect_verify() {
  local want=$1 text=${2:-}
  run_verify
  sed 's/^/    | /' "$WORKDIR/verify.out"
  if ((VERIFY_RC != want)); then
    die "pod-verify exited $VERIFY_RC, expected $want"
  fi
  if [[ -n $text ]] && ! grep -q "$text" "$WORKDIR/verify.out"; then
    die "pod-verify output does not contain \"$text\""
  fi
  info "pod-verify exited $VERIFY_RC, as expected"
}

operator_alive() {
  [[ -n $OPERATOR_PID ]] && kill -0 "$OPERATOR_PID" 2>/dev/null
}

operator_validated() {
  operator_alive || die "operator exited during startup"
  grep -q 'chain validated' "$WORKDIR/operator.log"
}

# verified_pass polls pod-verify while the operator publishes. Exit 1 (FAIL:
# not attested yet) means keep waiting; exit 2 means the verifier could not
# reach an answer, which waiting will not fix.
verified_pass() {
  operator_alive || die "operator exited before the Deployment was attested"
  run_verify
  if ((VERIFY_RC == 2)); then
    die "pod-verify could not reach an answer (exit 2)"
  fi
  ((VERIFY_RC == 0))
}

localstack_ready() {
  curl -sf "http://127.0.0.1:$KMS_PORT/_localstack/health" 2>/dev/null |
    grep -Eq '"kms": *"(available|running)"'
}

chain_ready() {
  curl -sf -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "$ETH_RPC_URL" 2>/dev/null | grep -q '"result":"0x7a69"'
}

# ---------------------------------------------------------------------------

log "run $RUN_ID: checking prerequisites"
for tool in docker kind kubectl aws go node curl python3 od; do
  command -v "$tool" >/dev/null || die "required tool not found on PATH: $tool"
done
docker info >/dev/null 2>&1 || die "docker is not running"

log "building operator and verifier"
make -C "$ROOT" build >/dev/null
[[ -x $MANAGER && -x $VERIFY ]] || die "build did not produce bin/manager and bin/pod-verify"

log "installing the contracts toolchain"
(cd "$ROOT/contracts" && npm ci --no-audit --no-fund --no-update-notifier --loglevel=error >/dev/null)

# --- KMS ---------------------------------------------------------------------
log "starting LocalStack KMS ($KMS_CONTAINER)"
KMS_PORT=$(free_port)
KMS_CREATED=1
docker run -d --name "$KMS_CONTAINER" -p "127.0.0.1:$KMS_PORT:4566" \
  -e SERVICES=kms localstack/localstack:4 >/dev/null
wait_until "$LOCALSTACK_TIMEOUT" "LocalStack KMS" localstack_ready

# Static throwaway credentials, scoped to this script's environment. The
# endpoint override means nothing here can reach real AWS.
unset AWS_PROFILE AWS_SESSION_TOKEN
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export AWS_ENDPOINT_URL_KMS=http://127.0.0.1:$KMS_PORT
export AWS_EC2_METADATA_DISABLED=true

KMS_KEY_ID=$(aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --query KeyMetadata.KeyId --output text)
info "KMS key $KMS_KEY_ID"

# The verifier is given the public key as a file, the way a real verifier would
# hold a key it trusts independently of the chain and the cluster.
aws kms get-public-key --key-id "$KMS_KEY_ID" --query PublicKey --output text |
  python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' \
    >"$WORKDIR/signer.der"
[[ -s $WORKDIR/signer.der ]] || die "could not fetch the KMS public key"

# --- chain -------------------------------------------------------------------
CHAIN_PORT=$(free_port)
ETH_RPC_URL=http://127.0.0.1:$CHAIN_PORT
log "starting a Hardhat node on $ETH_RPC_URL"
(cd "$ROOT/contracts" && exec ./node_modules/.bin/hardhat node --port "$CHAIN_PORT") \
  >"$WORKDIR/hardhat.log" 2>&1 &
HARDHAT_PID=$!
wait_until "$CHAIN_TIMEOUT" "the Hardhat node" chain_ready

log "deploying AttestationRegistryV2"
(cd "$ROOT/contracts" && DEMO_RPC_URL=$ETH_RPC_URL \
  ./node_modules/.bin/hardhat run scripts/deploy.js --network demo) >"$WORKDIR/deploy.log" 2>&1 ||
  { cat "$WORKDIR/deploy.log" >&2; die "contract deployment failed"; }
CONTRACT_ADDRESS=$(sed -n 's/^ *CONTRACT_ADDRESS=\(0x[0-9a-fA-F]\{40\}\)$/\1/p' "$WORKDIR/deploy.log")
[[ -n $CONTRACT_ADDRESS ]] || { cat "$WORKDIR/deploy.log" >&2; die "no contract address in deploy output"; }
info "registry at $CONTRACT_ADDRESS"

# --- cluster -----------------------------------------------------------------
log "creating kind cluster $CLUSTER"
CLUSTER_CREATED=1
if ! kind create cluster --name "$CLUSTER" --kubeconfig "$KCFG" \
  --wait "${CLUSTER_TIMEOUT}s" >"$WORKDIR/kind.log" 2>&1; then
  cat "$WORKDIR/kind.log" >&2
  if grep -q 'Multi-User System' "$WORKDIR/kind.log"; then
    # The node's systemd never finished booting. By far the most common cause
    # is the Docker host running out of inotify instances, usually because
    # other kind clusters are already running there.
    printf '\nHint: the kind node did not boot. Usually the Docker host is out of\n' >&2
    printf 'inotify instances (other kind clusters running?). See\n' >&2
    printf 'https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files\n' >&2
  fi
  die "kind cluster creation failed"
fi

log "deploying the demo workload"
kc apply -f "$ROOT/config/samples/demo-deployment.yaml" >/dev/null
kc -n demo rollout status deploy/api --timeout="${ROLLOUT_TIMEOUT}s"
ORIGINAL_UID=$(kc -n demo get deploy api -o jsonpath='{.metadata.uid}')
info "demo/api uid $ORIGINAL_UID"

# --- 1. PASS -----------------------------------------------------------------
log "starting the operator (cluster id $CLUSTER_ID)"
PROBE_PORT=$(free_port)
KUBECONFIG=$KCFG \
  KMS_KEY_ID=$KMS_KEY_ID \
  ETH_RPC_URL=$ETH_RPC_URL \
  CONTRACT_ADDRESS=$CONTRACT_ADDRESS \
  ETH_PRIVATE_KEY=$ETH_PRIVATE_KEY \
  CHAIN_ID=31337 \
  CLUSTER_ID=$CLUSTER_ID \
  "$MANAGER" --metrics-bind-address=0 --health-probe-bind-address="127.0.0.1:$PROBE_PORT" \
  >"$WORKDIR/operator.log" 2>&1 &
OPERATOR_PID=$!
wait_until "$OPERATOR_START_TIMEOUT" "operator startup validation" operator_validated
info "operator validated the chain, contract and publisher"

log "step 1: waiting for the operator to attest demo/api, expecting PASS"
wait_until "$PUBLISH_TIMEOUT" "a PASS for demo/api" verified_pass
expect_verify 0 "PASS  demo/api"

# --- 2. FAIL -----------------------------------------------------------------
log "pausing publication: stopping the operator"
stop_operator
info "operator stopped; it stays stopped for the rest of the demo"

log "step 2: privilege escalation, same image (privileged + hostPID), expecting FAIL"
kc -n demo patch deploy api --type=json -p '[
  {"op": "add", "path": "/spec/template/spec/hostPID", "value": true},
  {"op": "add", "path": "/spec/template/spec/containers/0/securityContext", "value": {"privileged": true}}
]' >/dev/null
kc -n demo rollout status deploy/api --timeout="${ROLLOUT_TIMEOUT}s"
expect_verify 1 "config hash mismatch"

# --- 3. PASS again -----------------------------------------------------------
log "step 3: reverting the change on the same object, expecting PASS"
kc -n demo patch deploy api --type=json -p '[
  {"op": "remove", "path": "/spec/template/spec/hostPID"},
  {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext"}
]' >/dev/null
kc -n demo rollout status deploy/api --timeout="${ROLLOUT_TIMEOUT}s"
RESTORED_UID=$(kc -n demo get deploy api -o jsonpath='{.metadata.uid}')
[[ $RESTORED_UID == "$ORIGINAL_UID" ]] || die "demo/api was recreated (uid $RESTORED_UID); the demo must restore in place"
expect_verify 0 "PASS  demo/api"
