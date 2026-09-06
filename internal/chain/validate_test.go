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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const validateTimeout = 30 * time.Second

// --- configuration, no network ----------------------------------------------

func TestParseAddressIsStrict(t *testing.T) {
	// common.HexToAddress silently truncates long input and left-pads short
	// input, so a typo becomes a valid-looking address pointing elsewhere. Each
	// of these must be rejected rather than quietly repaired.
	bad := map[string]string{
		"empty":           "",
		"no prefix":       "5FbDB2315678afecb367f032d93F642f64180aa3",
		"too short":       "0x5FbDB2315678afecb367f032d93F642f64180aa",
		"too long":        "0x5FbDB2315678afecb367f032d93F642f64180aa33",
		"non-hex":         "0xZZbDB2315678afecb367f032d93F642f64180aa3",
		"zero address":    "0x0000000000000000000000000000000000000000",
		"whitespace":      " 0x5FbDB2315678afecb367f032d93F642f64180aa3",
		"decimal garbage": "12345",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAddress(in); err == nil {
				t.Errorf("accepted %q", in)
			}
		})
	}
	if _, err := ParseAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"); err != nil {
		t.Errorf("rejected a valid address: %v", err)
	}
}

func TestValidateConfigRejectsBadInput(t *testing.T) {
	good := Config{
		RPCURL:          "http://127.0.0.1:8545",
		ContractAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		ChainID:         31337,
		PrivateKeyHex:   hardhatAccount1,
	}
	if _, err := ValidateConfig(good); err != nil {
		t.Fatalf("rejected a valid config: %v", err)
	}

	cases := map[string]func(Config) Config{
		"empty rpc":       func(c Config) Config { c.RPCURL = ""; return c },
		"rpc not a url":   func(c Config) Config { c.RPCURL = "not a url"; return c },
		"rpc bad scheme":  func(c Config) Config { c.RPCURL = "ftp://host"; return c },
		"zero chain id":   func(c Config) Config { c.ChainID = 0; return c },
		"negative chain":  func(c Config) Config { c.ChainID = -1; return c },
		"bad address":     func(c Config) Config { c.ContractAddress = "0x00"; return c },
		"bad private key": func(c Config) Config { c.PrivateKeyHex = "not-a-key"; return c },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateConfig(mutate(good))
			if err == nil {
				t.Fatal("accepted invalid configuration")
			}
			if !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("error is not ErrConfigInvalid: %v", err)
			}
		})
	}
}

func TestValidateConfigNeverEchoesTheKey(t *testing.T) {
	// A configuration error must not leak key material into logs.
	secret := "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	_, err := ValidateConfig(Config{
		RPCURL:          "http://127.0.0.1:8545",
		ContractAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		ChainID:         31337,
		PrivateKeyHex:   secret + "GG", // invalid on purpose
	})
	if err == nil {
		t.Fatal("accepted an invalid key")
	}
	if strings.Contains(err.Error(), secret[:16]) {
		t.Fatalf("the error contains key material: %v", err)
	}
}

// --- immutable splicing -----------------------------------------------------

func TestExpectedRuntimeFillsEveryImmutableOffset(t *testing.T) {
	// The compiler emits the immutable once per read site -- two here. Filling
	// only the first would leave part of the code unverified, and this is the
	// test that would catch that.
	if len(RegistryV2PublisherImmutables) < 2 {
		t.Fatalf("expected more than one immutable offset, got %d; "+
			"if the contract really changed, confirm the splicing still covers all of them",
			len(RegistryV2PublisherImmutables))
	}

	addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	got, err := ExpectedRuntime(addr)
	if err != nil {
		t.Fatalf("ExpectedRuntime: %v", err)
	}
	tmpl, err := hex.DecodeString(strings.TrimPrefix(RegistryV2DeployedTemplate, "0x"))
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	if len(got) != len(tmpl) {
		t.Fatalf("length changed: %d vs %d", len(got), len(tmpl))
	}

	for _, ref := range RegistryV2PublisherImmutables {
		slot := got[ref.Start : ref.Start+ref.Length]
		// An address sits in the low 20 bytes of the 32-byte word.
		if !bytes.Equal(slot[ref.Length-common.AddressLength:], addr.Bytes()) {
			t.Errorf("offset %d does not hold the publisher", ref.Start)
		}
		if !bytes.Equal(slot[:ref.Length-common.AddressLength], make([]byte, ref.Length-common.AddressLength)) {
			t.Errorf("offset %d has a non-zero high word", ref.Start)
		}
	}

	// Nothing outside the declared offsets may change.
	diff := got
	for _, ref := range RegistryV2PublisherImmutables {
		copy(diff[ref.Start:ref.Start+ref.Length], tmpl[ref.Start:ref.Start+ref.Length])
	}
	if !bytes.Equal(diff, tmpl) {
		t.Error("splicing modified bytes outside the immutable offsets")
	}
}

func TestExpectedRuntimeDistinguishesPublishers(t *testing.T) {
	a, err := ExpectedRuntime(common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ExpectedRuntime(common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the same runtime is expected for two different publishers; the immutable is not being checked")
	}
}

// --- drift ------------------------------------------------------------------

// TestRuntimeTemplateMatchesBuildInfo regenerates the pinned values from
// Hardhat's build-info.
//
// The pinned template must be in the binary, not read from disk: in a container
// the artifact is absent, and if present, anyone able to write it could choose
// what the operator accepts as the expected contract. That makes drift possible
// in the other direction, which is what this closes.
func TestRuntimeTemplateMatchesBuildInfo(t *testing.T) {
	matches, err := filepath.Glob("../../contracts/artifacts/build-info/*.json")
	if err != nil || len(matches) == 0 {
		t.Skip("no build-info (run `make contracts-compile`)")
	}

	type deployed struct {
		Object              string                                   `json:"object"`
		ImmutableReferences map[string][]struct{ Start, Length int } `json:"immutableReferences"`
	}
	var (
		found bool
		dep   deployed
		solc  string
	)
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var bi struct {
			SolcLongVersion string `json:"solcLongVersion"`
			Output          struct {
				Contracts map[string]map[string]struct {
					EVM struct {
						DeployedBytecode deployed `json:"deployedBytecode"`
					} `json:"evm"`
				} `json:"contracts"`
			} `json:"output"`
		}
		if err := json.Unmarshal(raw, &bi); err != nil {
			continue
		}
		for _, contracts := range bi.Output.Contracts {
			if c, ok := contracts["AttestationRegistryV2"]; ok {
				dep, solc, found = c.EVM.DeployedBytecode, bi.SolcLongVersion, true
			}
		}
	}
	if !found {
		t.Skip("AttestationRegistryV2 not in build-info")
	}

	if solc != RegistryV2SolcVersion {
		t.Errorf("solc changed: pinned %q, build-info %q -- regenerate the pinned runtime", RegistryV2SolcVersion, solc)
	}
	if dep.Object != strings.TrimPrefix(RegistryV2DeployedTemplate, "0x") {
		t.Error("the deployed bytecode template drifted from the compiled contract -- regenerate it")
	}

	var want []ImmutableRef
	for _, occs := range dep.ImmutableReferences {
		for _, o := range occs {
			want = append(want, ImmutableRef{Start: o.Start, Length: o.Length})
		}
	}
	if len(want) != len(RegistryV2PublisherImmutables) {
		t.Fatalf("immutable offsets changed: pinned %d, compiled %d", len(RegistryV2PublisherImmutables), len(want))
	}
	for _, w := range want {
		var seen bool
		for _, p := range RegistryV2PublisherImmutables {
			if p == w {
				seen = true
			}
		}
		if !seen {
			t.Errorf("compiled immutable %+v is not pinned", w)
		}
	}
}

// --- against a real chain ---------------------------------------------------

func TestValidateAcceptsTheRealContract(t *testing.T) {
	rc := newRealChain(t)
	cfg := Config{
		RPCURL:          rc.rpc,
		ContractAddress: rc.addr.Hex(),
		ChainID:         rc.chainID.Int64(),
		PrivateKeyHex:   rc.priv,
	}
	rep, err := Validate(context.Background(), cfg, true, validateTimeout)
	if err != nil {
		t.Fatalf("rejected a correctly deployed contract: %v", err)
	}
	if rep.Publisher != rep.Signer {
		t.Errorf("publisher %s != signer %s", rep.Publisher, rep.Signer)
	}
	if rep.Contract != rc.addr {
		t.Errorf("contract %s != %s", rep.Contract, rc.addr)
	}
}

func TestValidateRejectsWrongChainID(t *testing.T) {
	rc := newRealChain(t)
	cfg := Config{
		RPCURL: rc.rpc, ContractAddress: rc.addr.Hex(),
		ChainID: rc.chainID.Int64() + 1, PrivateKeyHex: rc.priv,
	}
	_, err := Validate(context.Background(), cfg, true, validateTimeout)
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("got %v, want ErrChainIDMismatch", err)
	}
}

func TestValidateRejectsAnAddressWithNoCode(t *testing.T) {
	rc := newRealChain(t)
	// A funded account, not a contract: exactly the mistake of pasting an EOA.
	eoa := crypto.PubkeyToAddress(mustKey(t, hardhatAccount1).PublicKey)
	cfg := Config{
		RPCURL: rc.rpc, ContractAddress: eoa.Hex(),
		ChainID: rc.chainID.Int64(), PrivateKeyHex: rc.priv,
	}
	_, err := Validate(context.Background(), cfg, true, validateTimeout)
	if !errors.Is(err, ErrNoContractCode) {
		t.Fatalf("got %v, want ErrNoContractCode", err)
	}
}

func TestValidateRejectsADifferentContract(t *testing.T) {
	// The v1 registry also exposes publisher(), so it answers the call. Only
	// comparing the code catches it.
	rc := newRealChain(t)
	other := deployArtifact(t, rc, "AttestationRegistry",
		crypto.PubkeyToAddress(mustKey(t, rc.priv).PublicKey))

	cfg := Config{
		RPCURL: rc.rpc, ContractAddress: other.Hex(),
		ChainID: rc.chainID.Int64(), PrivateKeyHex: rc.priv,
	}
	_, err := Validate(context.Background(), cfg, true, validateTimeout)
	if !errors.Is(err, ErrCodeMismatch) {
		t.Fatalf("got %v, want ErrCodeMismatch", err)
	}
}

func TestValidateRejectsAContractForAnotherPublisher(t *testing.T) {
	// Correct contract, correct code, wrong owner: the operator holds a key
	// that cannot write to it, which would surface as reverts on every publish.
	rc := newRealChain(t)
	stranger := crypto.PubkeyToAddress(mustKey(t, hardhatAccount1).PublicKey)
	foreign := deployArtifact(t, rc, "AttestationRegistryV2", stranger)

	cfg := Config{
		RPCURL: rc.rpc, ContractAddress: foreign.Hex(),
		ChainID: rc.chainID.Int64(), PrivateKeyHex: rc.priv,
	}
	_, err := Validate(context.Background(), cfg, true, validateTimeout)
	if !errors.Is(err, ErrPublisherMismatch) {
		t.Fatalf("got %v, want ErrPublisherMismatch", err)
	}

	// A reader has no expected account, so the same contract is fine for it:
	// the code is validated against whatever publisher the contract reports.
	readerCfg := cfg
	readerCfg.PrivateKeyHex = ""
	rep, err := Validate(context.Background(), readerCfg, false, validateTimeout)
	if err != nil {
		t.Fatalf("a reader rejected a valid contract it does not own: %v", err)
	}
	if rep.Publisher != stranger {
		t.Errorf("reader reported publisher %s, want %s", rep.Publisher, stranger)
	}
}

func TestValidateRejectsAnUnreachableRPC(t *testing.T) {
	cfg := Config{
		// A port nothing listens on.
		RPCURL:          "http://127.0.0.1:1",
		ContractAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		ChainID:         31337,
		PrivateKeyHex:   hardhatAccount1,
	}
	_, err := Validate(context.Background(), cfg, true, 3*time.Second)
	if !errors.Is(err, ErrChainUnreachable) {
		t.Fatalf("got %v, want ErrChainUnreachable", err)
	}
}

// deployArtifact deploys a named compiled contract with one constructor
// argument, and returns its address.
func deployArtifact(t *testing.T, rc *realChain, name string, arg common.Address) common.Address {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(
		"../../contracts/artifacts/contracts/" + name + ".sol/" + name + ".json"))
	if err != nil {
		t.Skipf("artifact for %s not found: %v", name, err)
	}
	var artifact struct {
		ABI      json.RawMessage `json:"abi"`
		Bytecode string          `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(mustKey(t, rc.priv), rc.chainID)
	if err != nil {
		t.Fatalf("transactor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()
	addr, tx, _, err := bind.DeployContract(auth, parsed, common.FromHex(artifact.Bytecode), rc.ec, arg)
	if err != nil {
		t.Fatalf("deploy %s: %v", name, err)
	}
	if _, err := bind.WaitMined(ctx, rc.ec, tx); err != nil {
		t.Fatalf("deploy %s not mined: %v", name, err)
	}
	return addr
}
