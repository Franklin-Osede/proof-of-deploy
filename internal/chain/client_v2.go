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
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ClientV2 is the typed wrapper around AttestationRegistryV2.
//
// It is a separate type from Client rather than an extension of it: the v2
// path is built alongside the v1 one and switched over once it is tested, so
// that a half-migrated client can never be what the operator is running.
//
// Publishing waits for the transaction to be MINED and reports the receipt
// status. "Mined" is the honest word: this waits for inclusion in a block, not
// for finality, and a reorg can still undo it.
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
	c, err := newClientV2(ec, common.HexToAddress(contractAddr))
	if err != nil {
		return nil, err
	}
	c.ec = ec
	return c, nil
}

// newClientV2 binds the registry to an arbitrary backend.
//
// Exists so the client can be bound to any backend rather than only a dialed
// endpoint. The round-trip test uses a throwaway Hardhat node through this
// seam; go-ethereum's in-process simulated backend was tried first and is not
// usable, because it pulls in github.com/fjl/memsize which does not link on
// current Go toolchains.
func newClientV2(backend bind.ContractBackend, addr common.Address) (*ClientV2, error) {
	parsed, err := abi.JSON(strings.NewReader(RegistryV2ABI))
	if err != nil {
		return nil, fmt.Errorf("chain: parse v2 ABI: %w", err)
	}
	return &ClientV2{
		contract: bind.NewBoundContract(addr, parsed, backend, backend, backend),
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

// PublishOutcome is what actually became of a submitted transaction.
//
// There are three, not two, because "we do not know" is a real answer and
// collapsing it into failure is what causes duplicate publications: a
// transaction that was replaced, or simply not seen in time, may well have
// landed. The caller must reconcile against contract state before resending.
type PublishOutcome int

const (
	// OutcomeUnknown means the transaction was submitted but not observed in a
	// block within the timeout. It is neither success nor failure.
	OutcomeUnknown PublishOutcome = iota
	// OutcomeMinedSuccess means a receipt was retrieved with status 1. This is
	// mined, not finalized: a reorg can still undo it.
	OutcomeMinedSuccess
	// OutcomeReverted means a receipt was retrieved with status 0. The
	// transaction definitively did not take effect, so it is safe to retry.
	OutcomeReverted
)

func (o PublishOutcome) String() string {
	switch o {
	case OutcomeMinedSuccess:
		return "mined-success"
	case OutcomeReverted:
		return "reverted"
	default:
		return "unknown"
	}
}

// PublishResult describes the fate of a publish attempt.
type PublishResult struct {
	TxHash      string
	Outcome     PublishOutcome
	BlockNumber uint64
	GasUsed     uint64
}

// publishTimeout bounds how long we wait for inclusion before returning
// OutcomeUnknown. It is not a failure threshold; it is how long we are willing
// to hold a worker before going and asking the contract instead.
const publishTimeout = 90 * time.Second

// SubmitOutcome distinguishes a transaction we know was accepted from one whose
// submission is itself uncertain.
//
// The distinction matters because eth_sendRawTransaction can be accepted while
// the response is lost to a network cut. The error the caller sees is then
// indistinguishable from "never sent", and treating it as such invites a
// duplicate publication. Anything that fails BEFORE the transaction is signed
// -- invalid parameters, no key, a failed nonce or gas lookup -- is
// unambiguous and stays an ordinary error.
type SubmitOutcome int

const (
	// SubmitUnknown means the transaction was signed and handed to the node,
	// but we do not know whether the node took it. It may be in the mempool.
	SubmitUnknown SubmitOutcome = iota
	// SubmitAccepted means the node acknowledged the transaction.
	SubmitAccepted
)

// SubmitResult reports what happened to a signed transaction. TxHash is known
// in both cases, because the transaction is signed locally before it is sent --
// which is what makes reconciliation possible after a lost response.
type SubmitResult struct {
	TxHash  common.Hash
	Outcome SubmitOutcome
}

// Submit builds, signs and sends a publish transaction WITHOUT waiting.
//
// The hash is computed before the send, so a transport failure still yields a
// hash the caller can reconcile with. An error means the transaction was never
// signed; a SubmitUnknown outcome means it may or may not have reached the
// node.
func (c *ClientV2) Submit(
	ctx context.Context,
	workloadID [32]byte,
	hashVersion uint16,
	configHash [32]byte,
	incarnation [32]byte,
	signature []byte,
	fingerprint [32]byte,
) (SubmitResult, error) {
	if c.auth == nil {
		return SubmitResult{}, fmt.Errorf("chain: client is read-only; no signing key configured")
	}
	if hashVersion == 0 {
		return SubmitResult{}, fmt.Errorf("chain: hash version 0 is not a valid protocol version")
	}
	if len(signature) == 0 {
		return SubmitResult{}, fmt.Errorf("chain: refusing to publish an empty signature")
	}

	// NoSend builds and signs without dispatching, so the hash is known before
	// anything leaves this process. Failures up to here -- nonce lookup, gas
	// estimation, signing -- are unambiguously "not submitted".
	opts := *c.auth
	opts.Context = ctx
	opts.NoSend = true
	tx, err := c.contract.Transact(&opts, "publish",
		workloadID, hashVersion, configHash, incarnation, signature, fingerprint)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("chain: build publish tx: %w", err)
	}

	res := SubmitResult{TxHash: tx.Hash(), Outcome: SubmitUnknown}
	if err := c.ec.SendTransaction(ctx, tx); err != nil {
		// Signed and possibly delivered. Not an error: only contract state can
		// settle whether it landed.
		return res, nil
	}
	res.Outcome = SubmitAccepted
	return res, nil
}

// PublishAndWait submits a publish transaction and waits for it to be mined.
//
// It returns an error only for failures that occurred BEFORE the transaction
// was signed. From the moment a signed transaction exists, every uncertainty is
// carried in the result rather than in an error, because the caller must
// reconcile against contract state instead of resending blindly.
//
// Context cancellation during the wait yields OutcomeUnknown and no error, so a
// shutdown is not recorded as a failed publication.
func (c *ClientV2) PublishAndWait(
	ctx context.Context,
	workloadID [32]byte,
	hashVersion uint16,
	configHash [32]byte,
	incarnation [32]byte,
	signature []byte,
	fingerprint [32]byte,
) (PublishResult, error) {
	sub, err := c.Submit(ctx, workloadID, hashVersion, configHash, incarnation, signature, fingerprint)
	if err != nil {
		return PublishResult{}, err
	}
	res := PublishResult{TxHash: sub.TxHash.Hex(), Outcome: OutcomeUnknown}
	if sub.Outcome == SubmitUnknown {
		// The node may or may not have it. Waiting on a hash it never saw would
		// just burn the timeout, so hand the hash back for reconciliation.
		return res, nil
	}

	tx, _, err := c.ec.TransactionByHash(ctx, sub.TxHash)
	if err != nil {
		// Accepted, but we cannot look it up. Unknown, not failed.
		return res, nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	rcpt, err := bind.WaitMined(waitCtx, c.ec, tx)
	if err != nil {
		// Timed out, or the caller cancelled. Either way the transaction may
		// still land; only contract state can settle it.
		return res, nil
	}

	res.BlockNumber = rcpt.BlockNumber.Uint64()
	res.GasUsed = rcpt.GasUsed
	if rcpt.Status == ethtypes.ReceiptStatusSuccessful {
		res.Outcome = OutcomeMinedSuccess
	} else {
		res.Outcome = OutcomeReverted
	}
	return res, nil
}

// PublishAttestation submits a publish transaction and returns the tx hash
// without waiting. Callers that need to know whether it took effect must use
// PublishAndWait.
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
	return decodeAttestationV2(out)
}

// decodeAttestationV2 maps getLatest's seven return values onto the struct.
//
// Split out so it can be tested without a chain. It is the part of this client
// most able to fail silently: seven values, several sharing a width, so two
// transposed would still typecheck and still produce plausible-looking output.
// The ORDER here must match the Solidity return order exactly, which
// TestABIMatchesCompiledArtifact enforces from the other direction.
func decodeAttestationV2(out []interface{}) (AttestationV2, error) {
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
