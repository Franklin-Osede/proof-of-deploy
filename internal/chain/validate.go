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
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Startup validation.
//
// Every check here answers a question the operator would otherwise answer at
// the worst possible moment: the first publication, against a real chain, with
// gas already spent. Failing at startup turns a silent misconfiguration into a
// crash loop with a specific reason.
//
// Errors name the property that failed and never contain key material.

// Config is what the operator was told to talk to.
type Config struct {
	RPCURL          string
	ContractAddress string
	ChainID         int64
	// PrivateKeyHex is required for a writer and empty for a reader. It is
	// never logged, and never appears in an error.
	PrivateKeyHex string
}

// ValidationReport is what validation established, for logging at startup.
type ValidationReport struct {
	ChainID   int64
	Contract  common.Address
	Publisher common.Address
	// Signer is the address derived from the configured key. Zero for a reader.
	Signer common.Address
}

var (
	ErrConfigInvalid     = errors.New("chain: invalid configuration")
	ErrChainUnreachable  = errors.New("chain: RPC unreachable")
	ErrChainIDMismatch   = errors.New("chain: RPC reports a different chain id than configured")
	ErrNoContractCode    = errors.New("chain: no contract code at the configured address")
	ErrCodeMismatch      = errors.New("chain: deployed code is not the expected registry")
	ErrPublisherMismatch = errors.New("chain: contract publisher is not the configured account")
)

// hexAddress is deliberately strict. common.HexToAddress accepts anything: it
// silently truncates a long string and left-pads a short one, so a typo becomes
// a valid-looking address pointing somewhere else entirely. It must never be
// used as a validator.
var hexAddress = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// ParseAddress validates and parses a contract address.
func ParseAddress(s string) (common.Address, error) {
	if !hexAddress.MatchString(s) {
		return common.Address{}, fmt.Errorf("%w: address %q is not 0x followed by 40 hex digits", ErrConfigInvalid, s)
	}
	addr := common.HexToAddress(s)
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("%w: address is the zero address", ErrConfigInvalid)
	}
	return addr, nil
}

// ValidateConfig checks everything that can be checked without a network.
//
// Separated so a typo fails instantly and identically whether or not the RPC
// happens to be reachable.
func ValidateConfig(cfg Config) (ValidationReport, error) {
	var rep ValidationReport

	if cfg.RPCURL == "" {
		return rep, fmt.Errorf("%w: RPC URL is empty", ErrConfigInvalid)
	}
	u, err := url.Parse(cfg.RPCURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rep, fmt.Errorf("%w: RPC URL %q is not a valid absolute URL", ErrConfigInvalid, cfg.RPCURL)
	}
	switch u.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return rep, fmt.Errorf("%w: RPC URL scheme %q is not supported", ErrConfigInvalid, u.Scheme)
	}

	addr, err := ParseAddress(cfg.ContractAddress)
	if err != nil {
		return rep, err
	}
	rep.Contract = addr

	if cfg.ChainID <= 0 {
		return rep, fmt.Errorf("%w: chain id must be positive, got %d", ErrConfigInvalid, cfg.ChainID)
	}
	rep.ChainID = cfg.ChainID

	if cfg.PrivateKeyHex != "" {
		key, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.PrivateKeyHex, "0x"))
		if err != nil {
			// Deliberately does not echo the value.
			return rep, fmt.Errorf("%w: private key is not a valid secp256k1 key", ErrConfigInvalid)
		}
		rep.Signer = crypto.PubkeyToAddress(key.PublicKey)
	}
	return rep, nil
}

// ExpectedRuntime returns the runtime bytecode this build expects for a
// registry whose publisher is the given address.
//
// The publisher is spliced into every offset the compiler recorded, so the
// comparison covers the whole of the code INCLUDING the immutable. Masking the
// offsets out instead would leave the most security-relevant bytes -- which
// account may write -- unverified.
func ExpectedRuntime(publisher common.Address) ([]byte, error) {
	tmpl, err := hex.DecodeString(strings.TrimPrefix(RegistryV2DeployedTemplate, "0x"))
	if err != nil {
		return nil, fmt.Errorf("chain: pinned runtime template is not hex: %w", err)
	}
	out := make([]byte, len(tmpl))
	copy(out, tmpl)

	for _, ref := range RegistryV2PublisherImmutables {
		if ref.Start < 0 || ref.Length <= 0 || ref.Start+ref.Length > len(out) {
			return nil, fmt.Errorf("chain: immutable reference %+v is outside the runtime", ref)
		}
		if ref.Length < common.AddressLength {
			return nil, fmt.Errorf("chain: immutable slot of %d bytes cannot hold an address", ref.Length)
		}
		// An address occupies the low 20 bytes of a 32-byte word; the rest stay
		// zero, exactly as the EVM stores it.
		slot := out[ref.Start : ref.Start+ref.Length]
		for i := range slot {
			slot[i] = 0
		}
		copy(slot[ref.Length-common.AddressLength:], publisher.Bytes())
	}
	return out, nil
}

// Validate performs the full startup check and returns what it established.
//
// requireSigner selects the writer rules: the contract's publisher must be the
// account the operator holds the key for. A reader has no expected account, so
// it validates the code against whatever publisher the contract reports and
// leaves authorisation to the contract.
func Validate(ctx context.Context, cfg Config, requireSigner bool, timeout time.Duration) (ValidationReport, error) {
	rep, err := ValidateConfig(cfg)
	if err != nil {
		return rep, err
	}
	if requireSigner && cfg.PrivateKeyHex == "" {
		return rep, fmt.Errorf("%w: a signing key is required to publish", ErrConfigInvalid)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ec, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return rep, fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	defer ec.Close()

	observed, err := ec.ChainID(ctx)
	if err != nil {
		return rep, fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	if observed.Cmp(big.NewInt(cfg.ChainID)) != 0 {
		return rep, fmt.Errorf("%w: configured %d, RPC reports %s", ErrChainIDMismatch, cfg.ChainID, observed)
	}

	code, err := ec.CodeAt(ctx, rep.Contract, nil)
	if err != nil {
		return rep, fmt.Errorf("%w: reading code: %v", ErrChainUnreachable, err)
	}
	if len(code) == 0 {
		return rep, fmt.Errorf("%w: %s holds no code (an account, or the wrong address)", ErrNoContractCode, rep.Contract)
	}

	publisher, err := readPublisher(ctx, ec, rep.Contract)
	if err != nil {
		// A contract that cannot answer publisher() is not this contract.
		return rep, fmt.Errorf("%w: contract does not answer publisher(): %v", ErrCodeMismatch, err)
	}
	rep.Publisher = publisher

	expected, err := ExpectedRuntime(publisher)
	if err != nil {
		return rep, err
	}
	if !bytes.Equal(code, expected) {
		return rep, fmt.Errorf("%w: %s runs %d bytes that do not match the registry compiled by solc %s (expected %d bytes)",
			ErrCodeMismatch, rep.Contract, len(code), RegistryV2SolcVersion, len(expected))
	}

	if requireSigner && publisher != rep.Signer {
		return rep, fmt.Errorf("%w: contract publisher is %s, this operator signs as %s",
			ErrPublisherMismatch, publisher, rep.Signer)
	}
	return rep, nil
}

// readPublisher calls the contract's immutable publisher() getter.
func readPublisher(ctx context.Context, ec *ethclient.Client, addr common.Address) (common.Address, error) {
	parsed, err := abi.JSON(strings.NewReader(RegistryV2ABI))
	if err != nil {
		return common.Address{}, err
	}
	bound := bind.NewBoundContract(addr, parsed, ec, ec, ec)

	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "publisher"); err != nil {
		return common.Address{}, err
	}
	if len(out) != 1 {
		return common.Address{}, fmt.Errorf("publisher() returned %d values, want 1", len(out))
	}
	addrOut, ok := out[0].(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("publisher() returned %T, want an address", out[0])
	}
	return addrOut, nil
}
