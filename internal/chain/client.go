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

// Package chain is the typed wrapper around the AttestationRegistry contract.
// The operator uses a writer client (it pays testnet gas to publish); the
// verify CLI uses a read-only client (no key, no gas). The signing key for
// attestations lives in KMS and is unrelated to the Ethereum account used to
// pay gas — that account is a throwaway testnet wallet (see README).
package chain

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Attestation is the on-chain record for the latest converged state of a
// Deployment, as returned by getLatest.
type Attestation struct {
	ConfigHash        [32]byte
	Signature         []byte
	SignerFingerprint [32]byte
	BlockTimestamp    uint64
	// HashVersion is which off-chain protocol produced ConfigHash. It is kept
	// as a raw uint16 so this package stays a transport: interpreting it, and
	// refusing versions it does not implement, is the caller's job.
	HashVersion uint16
	Exists      bool
}

// Client wraps a bound AttestationRegistry contract. When auth is nil the
// client is read-only and PublishAttestation returns an error.
type Client struct {
	ec       *ethclient.Client
	contract *bind.BoundContract
	auth     *bind.TransactOpts
	address  common.Address
}

// NewReader dials an RPC endpoint and binds the registry for read-only calls.
// Used by the verify CLI.
func NewReader(ctx context.Context, rpcURL, contractAddr string) (*Client, error) {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("chain: dial %q: %w", rpcURL, err)
	}
	parsed, err := abi.JSON(strings.NewReader(RegistryABI))
	if err != nil {
		return nil, fmt.Errorf("chain: parse ABI: %w", err)
	}
	addr := common.HexToAddress(contractAddr)
	return &Client{
		ec:       ec,
		contract: bind.NewBoundContract(addr, parsed, ec, ec, ec),
		address:  addr,
	}, nil
}

// NewWriter is NewReader plus a keyed transactor for the given testnet chain ID.
// privHex is a TESTNET private key (with or without 0x) funded from a faucet;
// it pays gas and is never used for attestation signing. Used by the operator.
func NewWriter(ctx context.Context, rpcURL, contractAddr, privHex string, chainID *big.Int) (*Client, error) {
	c, err := NewReader(ctx, rpcURL, contractAddr)
	if err != nil {
		return nil, err
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("chain: parse testnet private key: %w", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		return nil, fmt.Errorf("chain: build transactor: %w", err)
	}
	c.auth = auth
	return c, nil
}

// PublishAttestation submits a publish transaction and returns the tx hash. It
// returns once the transaction is sent (not mined); the publisher's retry loop
// is responsible for resubmission on send failure.
func (c *Client) PublishAttestation(ctx context.Context, deploymentID [32]byte, hashVersion uint16, configHash [32]byte, signature []byte, fingerprint [32]byte) (string, error) {
	if c.auth == nil {
		return "", fmt.Errorf("chain: client is read-only; no signing key configured")
	}
	if hashVersion == 0 {
		// The contract rejects this too, but failing here keeps the wasted gas
		// and the confusing revert out of the picture entirely.
		return "", fmt.Errorf("chain: hash version 0 is not a valid protocol version")
	}
	opts := *c.auth
	opts.Context = ctx
	tx, err := c.contract.Transact(&opts, "publish", deploymentID, hashVersion, configHash, signature, fingerprint)
	if err != nil {
		return "", fmt.Errorf("chain: publish tx: %w", err)
	}
	return tx.Hash().Hex(), nil
}

// LatestAttestation reads the most recent attestation for a Deployment ID. The
// returned Attestation.Exists is false when nothing has been published yet.
func (c *Client) LatestAttestation(ctx context.Context, deploymentID [32]byte) (Attestation, error) {
	var out []interface{}
	if err := c.contract.Call(&bind.CallOpts{Context: ctx}, &out, "getLatest", deploymentID); err != nil {
		return Attestation{}, fmt.Errorf("chain: getLatest: %w", err)
	}
	if len(out) != 6 {
		return Attestation{}, fmt.Errorf("chain: getLatest returned %d values, want 6", len(out))
	}

	att := Attestation{}
	var ok bool
	if att.ConfigHash, ok = out[0].([32]byte); !ok {
		return Attestation{}, typeErr("configHash", out[0])
	}
	if att.Signature, ok = out[1].([]byte); !ok {
		return Attestation{}, typeErr("signature", out[1])
	}
	if att.SignerFingerprint, ok = out[2].([32]byte); !ok {
		return Attestation{}, typeErr("signerFingerprint", out[2])
	}
	if att.BlockTimestamp, ok = out[3].(uint64); !ok {
		return Attestation{}, typeErr("blockTimestamp", out[3])
	}
	if att.HashVersion, ok = out[4].(uint16); !ok {
		return Attestation{}, typeErr("hashVersion", out[4])
	}
	if att.Exists, ok = out[5].(bool); !ok {
		return Attestation{}, typeErr("exists", out[5])
	}
	return att, nil
}

// Address returns the registry contract address this client is bound to.
func (c *Client) Address() common.Address { return c.address }

// Close releases the underlying RPC connection.
func (c *Client) Close() {
	if c.ec != nil {
		c.ec.Close()
	}
}

func typeErr(field string, v interface{}) error {
	return fmt.Errorf("chain: unexpected ABI type for %s: %T", field, v)
}
