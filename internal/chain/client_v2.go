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
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ClientV2 is the typed wrapper around AttestationRegistryV2.
//
// It is a separate type from Client rather than an extension of it: the v2
// path is built alongside the v1 one and switched over once it is tested, so
// that a half-migrated client can never be what the operator is running.
//
// NOTE ON SCOPE: this client mirrors the v1 operations against the v2 contract
// and nothing more. In particular PublishAttestation still returns once the
// transaction is SENT, which is not the same as published. The
// pending/confirmed/retryable model, receipt waiting, and nonce handling arrive
// in a later step and will change this signature. That is deliberate — adding a
// receipt-shaped API now, without the waiting behind it, would be a lie in the
// type system.
type ClientV2 struct {
	ec       *ethclient.Client
	contract *bind.BoundContract
	auth     *bind.TransactOpts
	address  common.Address
}

// AttestationV2 is the on-chain record for the latest attested state of a
// workload, as returned by getLatest.
type AttestationV2 struct {
	ConfigHash        [32]byte
	Signature         []byte
	SignerFingerprint [32]byte
	// Incarnation is the fixed-width form of the observed object's Kubernetes
	// UID. All-zero means no incarnation was bound. Deciding what to do about
	// that is the verifier's job, not this package's.
	Incarnation    [32]byte
	BlockTimestamp uint64
	// HashVersion is kept as a raw uint16 so this package stays a transport.
	// Refusing versions it does not implement is the caller's responsibility.
	HashVersion uint16
	Exists      bool
}

// NewReaderV2 dials an RPC endpoint and binds the v2 registry for read-only
// calls. Used by the verify CLI.
//
// It does not yet validate that the address holds the contract it expects.
// Chain ID, bytecode and publisher checks arrive with startup validation.
func NewReaderV2(ctx context.Context, rpcURL, contractAddr string) (*ClientV2, error) {
	ec, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("chain: dial %q: %w", rpcURL, err)
	}
	parsed, err := abi.JSON(strings.NewReader(RegistryV2ABI))
	if err != nil {
		return nil, fmt.Errorf("chain: parse v2 ABI: %w", err)
	}
	addr := common.HexToAddress(contractAddr)
	return &ClientV2{
		ec:       ec,
		contract: bind.NewBoundContract(addr, parsed, ec, ec, ec),
		address:  addr,
	}, nil
}

// NewWriterV2 is NewReaderV2 plus a keyed transactor for the given testnet
// chain ID. privHex is a TESTNET private key that pays gas and is never used
// for attestation signing.
func NewWriterV2(ctx context.Context, rpcURL, contractAddr, privHex string, chainID *big.Int) (*ClientV2, error) {
	c, err := NewReaderV2(ctx, rpcURL, contractAddr)
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

// PublishAttestation submits a publish transaction and returns the tx hash.
//
// It returns once the transaction is SENT. A sent transaction is not a
// published one: it can be dropped, replaced or reverted. Treating this return
// as success is the behaviour the next step replaces.
func (c *ClientV2) PublishAttestation(
	ctx context.Context,
	workloadID [32]byte,
	hashVersion uint16,
	configHash [32]byte,
	incarnation [32]byte,
	signature []byte,
	fingerprint [32]byte,
) (string, error) {
	if c.auth == nil {
		return "", fmt.Errorf("chain: client is read-only; no signing key configured")
	}
	// Both are rejected on-chain too. Failing here keeps the wasted gas and the
	// opaque revert out of the picture.
	if hashVersion == 0 {
		return "", fmt.Errorf("chain: hash version 0 is not a valid protocol version")
	}
	if len(signature) == 0 {
		return "", fmt.Errorf("chain: refusing to publish an empty signature")
	}

	opts := *c.auth
	opts.Context = ctx
	tx, err := c.contract.Transact(&opts, "publish",
		workloadID, hashVersion, configHash, incarnation, signature, fingerprint)
	if err != nil {
		return "", fmt.Errorf("chain: publish tx: %w", err)
	}
	return tx.Hash().Hex(), nil
}

// LatestAttestation reads the most recent attestation for a workload ID.
// Exists is false when nothing has been published under that identity.
func (c *ClientV2) LatestAttestation(ctx context.Context, workloadID [32]byte) (AttestationV2, error) {
	var out []interface{}
	if err := c.contract.Call(&bind.CallOpts{Context: ctx}, &out, "getLatest", workloadID); err != nil {
		return AttestationV2{}, fmt.Errorf("chain: getLatest: %w", err)
	}
	if len(out) != 7 {
		return AttestationV2{}, fmt.Errorf("chain: getLatest returned %d values, want 7", len(out))
	}

	att := AttestationV2{}
	var ok bool
	if att.ConfigHash, ok = out[0].([32]byte); !ok {
		return AttestationV2{}, typeErr("configHash", out[0])
	}
	if att.Signature, ok = out[1].([]byte); !ok {
		return AttestationV2{}, typeErr("signature", out[1])
	}
	if att.SignerFingerprint, ok = out[2].([32]byte); !ok {
		return AttestationV2{}, typeErr("signerFingerprint", out[2])
	}
	if att.Incarnation, ok = out[3].([32]byte); !ok {
		return AttestationV2{}, typeErr("incarnation", out[3])
	}
	if att.BlockTimestamp, ok = out[4].(uint64); !ok {
		return AttestationV2{}, typeErr("blockTimestamp", out[4])
	}
	if att.HashVersion, ok = out[5].(uint16); !ok {
		return AttestationV2{}, typeErr("hashVersion", out[5])
	}
	if att.Exists, ok = out[6].(bool); !ok {
		return AttestationV2{}, typeErr("exists", out[6])
	}
	return att, nil
}

// Address returns the registry address this client is bound to.
func (c *ClientV2) Address() common.Address { return c.address }

// Close releases the underlying RPC connection.
func (c *ClientV2) Close() {
	if c.ec != nil {
		c.ec.Close()
	}
}
