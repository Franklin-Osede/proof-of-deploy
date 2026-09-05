/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package chain

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// b32 builds a recognisable 32-byte value: every byte the same, so a
// transposed field is obvious in a failure message rather than a hex soup.
func b32(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

// --- decoding ---------------------------------------------------------------
//
// getLatest returns seven values and several share a width, so two transposed
// would still typecheck and still produce plausible output. These fixtures give
// every field a distinct value precisely so that cannot pass.

func TestDecodeAttestationV2MapsEveryFieldToTheRightSlot(t *testing.T) {
	out := []interface{}{
		b32(0x11),                      // configHash
		[]byte{0xde, 0xad, 0xbe, 0xef}, // signature
		b32(0x22),                      // signerFingerprint
		b32(0x33),                      // incarnation
		uint64(1700000000),             // blockTimestamp
		uint16(2),                      // hashVersion
		true,                           // exists
	}

	got, err := decodeAttestationV2(out)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ConfigHash != b32(0x11) {
		t.Errorf("ConfigHash = %x, want %x", got.ConfigHash, b32(0x11))
	}
	if string(got.Signature) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("Signature = %x", got.Signature)
	}
	if got.SignerFingerprint != b32(0x22) {
		t.Errorf("SignerFingerprint = %x, want %x", got.SignerFingerprint, b32(0x22))
	}
	if got.Incarnation != b32(0x33) {
		t.Errorf("Incarnation = %x, want %x", got.Incarnation, b32(0x33))
	}
	if got.BlockTimestamp != 1700000000 {
		t.Errorf("BlockTimestamp = %d", got.BlockTimestamp)
	}
	if got.HashVersion != 2 {
		t.Errorf("HashVersion = %d", got.HashVersion)
	}
	if !got.Exists {
		t.Error("Exists = false")
	}
}

func TestDecodeAttestationV2RejectsMalformedReturns(t *testing.T) {
	valid := []interface{}{
		b32(0x11), []byte{0x01}, b32(0x22), b32(0x33), uint64(1), uint16(1), true,
	}

	t.Run("wrong arity", func(t *testing.T) {
		// A contract whose getLatest gained or lost a return value must be a
		// hard error, not a partially-filled struct.
		for _, n := range []int{0, 5, 6, 8} {
			trimmed := make([]interface{}, 0, n)
			for i := 0; i < n; i++ {
				trimmed = append(trimmed, valid[i%len(valid)])
			}
			if _, err := decodeAttestationV2(trimmed); err == nil {
				t.Errorf("%d values were accepted; want 7 enforced", n)
			}
		}
	})

	t.Run("wrong type in each slot", func(t *testing.T) {
		// Substituting a plausible-but-wrong type per slot. uint64 for a
		// bytes32, or uint32 for a uint16, is exactly what an ABI change would
		// produce.
		wrong := []interface{}{
			uint64(1), b32(0x01), uint64(1), uint64(1), uint16(1), uint64(1), uint16(1),
		}
		for i := range valid {
			mutated := append([]interface{}{}, valid...)
			mutated[i] = wrong[i]
			if _, err := decodeAttestationV2(mutated); err == nil {
				t.Errorf("slot %d accepted a %T", i, wrong[i])
			}
		}
	})
}

// --- client guards ----------------------------------------------------------
//
// These run before any transaction is built, so they need no chain. They exist
// so a doomed transaction is never paid for.

func TestClientV2RefusesDoomedPublishes(t *testing.T) {
	ctx := context.Background()
	readOnly := &ClientV2{}
	withKey := &ClientV2{auth: &bind.TransactOpts{}}

	t.Run("read-only client", func(t *testing.T) {
		if _, err := readOnly.PublishAttestation(ctx, b32(1), 1, b32(2), b32(3), []byte{1}, b32(4)); err == nil {
			t.Fatal("a client with no signing key published")
		}
	})
	t.Run("hash version zero", func(t *testing.T) {
		// Zero is what an unset record reads back as, so it can never be valid.
		if _, err := withKey.PublishAttestation(ctx, b32(1), 0, b32(2), b32(3), []byte{1}, b32(4)); err == nil {
			t.Fatal("version 0 was accepted")
		}
	})
	t.Run("empty signature", func(t *testing.T) {
		// It could never verify, so publishing it only wastes gas.
		if _, err := withKey.PublishAttestation(ctx, b32(1), 1, b32(2), b32(3), nil, b32(4)); err == nil {
			t.Fatal("an empty signature was accepted")
		}
	})
}

// --- round trip against a real chain ----------------------------------------
//
// Decoding alone could pass while the encoding side is wrong, so the symmetry
// needs a real EVM and the real compiled contract. go-ethereum's in-process
// simulated backend is not usable here: it pulls in github.com/fjl/memsize,
// which does not link on current Go toolchains.
//
// Runs when TEST_ETH_RPC_URL points at a throwaway node (the local Hardhat node
// from docs/local-demo.md), skips otherwise. TEST_ETH_PRIVATE_KEY must be a
// funded key on that node; it is a test key on a disposable chain and nothing
// else.

func TestV2RoundTripAgainstRealChain(t *testing.T) {
	rpc := os.Getenv("TEST_ETH_RPC_URL")
	priv := os.Getenv("TEST_ETH_PRIVATE_KEY")
	if rpc == "" || priv == "" {
		t.Skip("set TEST_ETH_RPC_URL and TEST_ETH_PRIVATE_KEY to run the round trip")
	}

	raw, err := os.ReadFile(filepath.Clean(
		"../../contracts/artifacts/contracts/AttestationRegistryV2.sol/AttestationRegistryV2.json"))
	if err != nil {
		t.Skipf("compiled artifact not found (run `make contracts-compile`): %v", err)
	}
	var artifact struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode string          `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ec, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ec.Close()
	chainID, err := ec.ChainID(ctx)
	if err != nil {
		t.Fatalf("chain id: %v", err)
	}

	key, err := crypto.HexToECDSA(strings.TrimPrefix(priv, "0x"))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		t.Fatalf("transactor: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)

	fullABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		t.Fatalf("parse artifact ABI: %v", err)
	}
	addr, tx, _, err := bind.DeployContract(auth, fullABI, common.FromHex(artifact.Bytecode), ec, from)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := bind.WaitMined(ctx, ec, tx); err != nil {
		t.Fatalf("deploy not mined: %v", err)
	}

	writer, err := NewWriterV2(ctx, rpc, addr.Hex(), priv, chainID)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	defer writer.Close()

	workloadID, configHash := b32(0xa1), b32(0xb2)
	incarnation, fingerprint := b32(0xc3), b32(0xd4)
	signature := []byte{0x30, 0x45, 0x02, 0x21, 0x00, 0xff}
	const version uint16 = 2

	txHash, err := writer.PublishAttestation(ctx, workloadID, version, configHash, incarnation, signature, fingerprint)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	rcpt, err := bind.WaitMined(ctx, ec, txFromHash(t, ctx, ec, txHash))
	if err != nil {
		t.Fatalf("publish not mined: %v", err)
	}
	if rcpt.Status != 1 {
		t.Fatalf("publish reverted, status %d", rcpt.Status)
	}

	got, err := writer.LatestAttestation(ctx, workloadID)
	if err != nil {
		t.Fatalf("getLatest: %v", err)
	}
	if !got.Exists {
		t.Fatal("record absent after a mined publish")
	}
	if got.ConfigHash != configHash || got.Incarnation != incarnation ||
		got.SignerFingerprint != fingerprint || got.HashVersion != version ||
		string(got.Signature) != string(signature) {
		t.Errorf("round trip changed the record: %+v", got)
	}
	if got.BlockTimestamp == 0 {
		t.Error("BlockTimestamp is zero")
	}

	// An identity that was never published must read back empty, not as an
	// attestation of zeros.
	absent, err := writer.LatestAttestation(ctx, b32(0xee))
	if err != nil {
		t.Fatalf("getLatest absent: %v", err)
	}
	if absent.Exists || absent.HashVersion != 0 || len(absent.Signature) != 0 {
		t.Errorf("an unpublished identity came back populated: %+v", absent)
	}
}

func txFromHash(t *testing.T, ctx context.Context, ec *ethclient.Client, hash string) *types.Transaction {
	t.Helper()
	tx, _, err := ec.TransactionByHash(ctx, common.HexToHash(hash))
	if err != nil {
		t.Fatalf("fetch tx %s: %v", hash, err)
	}
	return tx
}

// --- publish outcomes -------------------------------------------------------
//
// The three outcomes exist because "we do not know" is a real answer.
// Collapsing it into failure is what causes duplicate publications: a
// transaction that was replaced, or simply not seen in time, may well have
// landed.

// hardhatAccount1 is the second well-known account of a Hardhat dev node. It is
// funded but is NOT the deployed contract's publisher, which makes it the
// natural way to produce a genuine on-chain revert.
const hardhatAccount1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

type realChain struct {
	rpc     string
	priv    string
	ec      *ethclient.Client
	chainID *big.Int
	addr    common.Address
}

func newRealChain(t *testing.T) *realChain {
	t.Helper()
	rpc := os.Getenv("TEST_ETH_RPC_URL")
	priv := os.Getenv("TEST_ETH_PRIVATE_KEY")
	if rpc == "" || priv == "" {
		t.Skip("set TEST_ETH_RPC_URL and TEST_ETH_PRIVATE_KEY to run against a real node")
	}

	raw, err := os.ReadFile(filepath.Clean(
		"../../contracts/artifacts/contracts/AttestationRegistryV2.sol/AttestationRegistryV2.json"))
	if err != nil {
		t.Skipf("compiled artifact not found (run `make contracts-compile`): %v", err)
	}
	var artifact struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode string          `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ec, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(ec.Close)
	chainID, err := ec.ChainID(ctx)
	if err != nil {
		t.Fatalf("chain id: %v", err)
	}

	key, err := crypto.HexToECDSA(strings.TrimPrefix(priv, "0x"))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		t.Fatalf("transactor: %v", err)
	}
	fullABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		t.Fatalf("parse artifact ABI: %v", err)
	}
	addr, tx, _, err := bind.DeployContract(auth, fullABI, common.FromHex(artifact.Bytecode),
		ec, crypto.PubkeyToAddress(key.PublicKey))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := bind.WaitMined(ctx, ec, tx); err != nil {
		t.Fatalf("deploy not mined: %v", err)
	}
	return &realChain{rpc: rpc, priv: priv, ec: ec, chainID: chainID, addr: addr}
}

func (r *realChain) writer(t *testing.T, priv string) *ClientV2 {
	t.Helper()
	w, err := NewWriterV2(context.Background(), r.rpc, r.addr.Hex(), priv, r.chainID)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	t.Cleanup(w.Close)
	return w
}

// setAutomine toggles Hardhat's auto-mining. Returns false when the node does
// not support it, so the timeout case skips rather than lying.
func (r *realChain) setAutomine(t *testing.T, on bool) bool {
	t.Helper()
	var rpcClient = r.ec.Client()
	if err := rpcClient.CallContext(context.Background(), nil, "evm_setAutomine", on); err != nil {
		t.Logf("evm_setAutomine unsupported on this node: %v", err)
		return false
	}
	return true
}

func TestPublishAndWaitReportsMinedSuccess(t *testing.T) {
	rc := newRealChain(t)
	w := rc.writer(t, rc.priv)

	res, err := w.PublishAndWait(context.Background(),
		b32(0xa1), 2, b32(0xb2), b32(0xc3), []byte{0x30, 0x45}, b32(0xd4))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if res.Outcome != OutcomeMinedSuccess {
		t.Fatalf("outcome = %s, want mined-success", res.Outcome)
	}
	if res.BlockNumber == 0 || res.GasUsed == 0 || res.TxHash == "" {
		t.Errorf("receipt details missing: %+v", res)
	}

	got, err := w.LatestAttestation(context.Background(), b32(0xa1))
	if err != nil || !got.Exists || got.ConfigHash != b32(0xb2) {
		t.Errorf("a mined-success publish is not readable back: %+v (err %v)", got, err)
	}
}

func TestPublishAndWaitReportsRevert(t *testing.T) {
	rc := newRealChain(t)
	// Account 1 is funded but is not the contract's publisher, so onlyPublisher
	// rejects it. A revert must be an OUTCOME, not an error: it is definitive,
	// so the caller may safely retry, which is different from not knowing.
	if !rc.setAutomine(t, false) {
		t.Skip("node cannot pause mining")
	}
	t.Cleanup(func() { rc.setAutomine(t, true) })

	intruder := rc.writer(t, hardhatAccount1)
	// With auto-mining on, the node simulates and refuses a reverting
	// transaction before it is ever submitted. That is a legitimate rejection,
	// but it leaves the receipt-status branch -- the one that actually produces
	// OutcomeReverted -- unexercised. Queueing it first and mining afterwards
	// is what forces a genuinely mined revert.
	intruder.auth.GasLimit = 200000

	type outcome struct {
		res PublishResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := intruder.PublishAndWait(context.Background(),
			b32(0xa1), 2, b32(0xb2), b32(0xc3), []byte{0x30, 0x45}, b32(0xd4))
		done <- outcome{res, err}
	}()

	time.Sleep(500 * time.Millisecond)
	if err := rc.ec.Client().CallContext(context.Background(), nil, "evm_mine"); err != nil {
		t.Fatalf("evm_mine: %v", err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("submission failed before mining, so the revert path was not reached: %v", got.err)
		}
		if got.res.Outcome != OutcomeReverted {
			t.Fatalf("outcome = %s, want reverted", got.res.Outcome)
		}
		if got.res.BlockNumber == 0 {
			t.Error("a reverted transaction was still mined, so it must carry a block number")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("PublishAndWait did not return after the block was mined")
	}

	got, err := rc.writer(t, rc.priv).LatestAttestation(context.Background(), b32(0xa1))
	if err != nil {
		t.Fatalf("getLatest: %v", err)
	}
	if got.Exists {
		t.Error("a reverted transaction still wrote a record")
	}
}

func TestPublishAndWaitReportsUnknownWhenNotMined(t *testing.T) {
	rc := newRealChain(t)
	if !rc.setAutomine(t, false) {
		t.Skip("node cannot pause mining")
	}
	t.Cleanup(func() { rc.setAutomine(t, true) })
	w := rc.writer(t, rc.priv)

	// A deadline shorter than publishTimeout wins, so this does not wait 90s.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := w.PublishAndWait(ctx, b32(0xf1), 2, b32(0xf2), b32(0xf3), []byte{0x30, 0x45}, b32(0xf4))
	if err != nil {
		t.Fatalf("publish returned an error for an unmined transaction; it must be an outcome: %v", err)
	}
	if res.Outcome != OutcomeUnknown {
		t.Fatalf("outcome = %s, want unknown", res.Outcome)
	}
	if res.TxHash == "" {
		t.Error("no transaction hash returned; the caller cannot reconcile without one")
	}
}

func TestPublishAndWaitTreatsShutdownAsUnknown(t *testing.T) {
	rc := newRealChain(t)
	if !rc.setAutomine(t, false) {
		t.Skip("node cannot pause mining")
	}
	t.Cleanup(func() { rc.setAutomine(t, true) })
	w := rc.writer(t, rc.priv)

	// Cancelling mid-wait is a shutdown, not a failed publication: the
	// transaction may still land, and recording it as failed would invite a
	// duplicate on the next start.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(500 * time.Millisecond); cancel() }()

	res, err := w.PublishAndWait(ctx, b32(0xe1), 2, b32(0xe2), b32(0xe3), []byte{0x30, 0x45}, b32(0xe4))
	if err != nil {
		t.Fatalf("cancellation produced an error rather than an outcome: %v", err)
	}
	if res.Outcome != OutcomeUnknown {
		t.Fatalf("outcome = %s, want unknown after cancellation", res.Outcome)
	}
}

// TestSubmitKnowsTheHashBeforeSending is the property that makes reconciliation
// possible at all.
//
// eth_sendRawTransaction can be accepted while the response is lost, so an
// error from the send is NOT evidence the transaction is absent. Signing
// locally first means the hash is known either way, and the caller can go and
// ask the chain instead of guessing.
func TestSubmitKnowsTheHashBeforeSending(t *testing.T) {
	rc := newRealChain(t)
	if !rc.setAutomine(t, false) {
		t.Skip("node cannot pause mining")
	}
	t.Cleanup(func() { rc.setAutomine(t, true) })
	w := rc.writer(t, rc.priv)
	ctx := context.Background()

	wl, cfg := b32(0x71), b32(0x72)
	res, err := w.Submit(ctx, wl, 2, cfg, b32(0x73), []byte{0x30, 0x45}, b32(0x74))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.TxHash == (common.Hash{}) {
		t.Fatal("no hash returned; reconciliation would have nothing to go on")
	}

	// Nothing is mined yet, so the hash cannot have come from a receipt: it was
	// computed locally from the signed transaction.
	if got, err := w.LatestAttestation(ctx, wl); err != nil || got.Exists {
		t.Fatalf("record already present before mining (err %v); the test premise is wrong", err)
	}

	if err := rc.ec.Client().CallContext(ctx, nil, "evm_mine"); err != nil {
		t.Fatalf("evm_mine: %v", err)
	}
	got, err := w.LatestAttestation(ctx, wl)
	if err != nil {
		t.Fatalf("getLatest: %v", err)
	}
	if !got.Exists || got.ConfigHash != cfg {
		t.Fatal("the submitted transaction never landed")
	}
	t.Logf("hash %s… was known before the send and the record landed", res.TxHash.Hex()[:18])
}

// TestResendWithoutReconcilingPublishesTwice is why reconciliation is mandatory
// rather than merely tidy.
//
// A retry does NOT resubmit the same transaction. Each attempt takes a fresh
// pending nonce, so it builds and signs a DIFFERENT transaction with a
// different hash — and both are valid, so both mine. Anything that treats an
// unknown outcome as "probably failed, send it again" therefore writes twice.
//
// The publisher must query getLatest and only resend when the record is still
// absent. This test exists so that requirement cannot be quietly dropped.
func TestResendWithoutReconcilingPublishesTwice(t *testing.T) {
	rc := newRealChain(t)
	if !rc.setAutomine(t, false) {
		t.Skip("node cannot pause mining")
	}
	t.Cleanup(func() { rc.setAutomine(t, true) })
	w := rc.writer(t, rc.priv)
	ctx := context.Background()

	wl := b32(0x81)
	first, err := w.Submit(ctx, wl, 2, b32(0x82), b32(0x83), []byte{0x30, 0x45}, b32(0x84))
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Same arguments, no reconciliation in between: exactly what a naive retry
	// after an unknown outcome would do.
	second, err := w.Submit(ctx, wl, 2, b32(0x82), b32(0x83), []byte{0x30, 0x45}, b32(0x84))
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}

	if first.TxHash == second.TxHash {
		t.Skip("this node deduplicated the resend, so the hazard cannot be shown here")
	}
	t.Logf("a naive retry produced a second distinct transaction: %s… and %s…",
		first.TxHash.Hex()[:12], second.TxHash.Hex()[:12])

	if err := rc.ec.Client().CallContext(ctx, nil, "evm_mine"); err != nil {
		t.Fatalf("evm_mine: %v", err)
	}

	// Both transactions are valid publishes, so both take effect. The registry
	// is latest-only, so the second silently overwrote the first — and on a
	// real network that is two lots of gas for one attestation, plus two
	// events where a consumer expected one.
	mined := 0
	for _, h := range []common.Hash{first.TxHash, second.TxHash} {
		rcpt, err := rc.ec.TransactionReceipt(ctx, h)
		if err != nil {
			continue
		}
		if rcpt.Status == 1 {
			mined++
		}
	}
	if mined < 2 {
		t.Fatalf("only %d of the two resends mined; the duplicate-publication hazard is not reproduced", mined)
	}
	t.Log("confirmed: both publications landed. A retry must reconcile against getLatest before resending.")
}
