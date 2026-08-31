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
