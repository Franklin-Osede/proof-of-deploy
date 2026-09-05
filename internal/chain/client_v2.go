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

// SubmitOutcome distinguishes a transaction we know the node accepted from one
// whose delivery is itself uncertain.
//
// eth_sendRawTransaction can be accepted while the response is lost to a
// network cut, and the error the caller then sees is indistinguishable from
// "never sent". Treating that as failure invites a duplicate publication.
type SubmitOutcome int

const (
	// SubmitUnknown means the signed transaction was handed to the node but we
	// do not know whether it took it. It may be in the mempool.
	SubmitUnknown SubmitOutcome = iota
	// SubmitAccepted means the node acknowledged the transaction.
	SubmitAccepted
)

func (o SubmitOutcome) String() string {
	if o == SubmitAccepted {
		return "accepted"
	}
	return "unknown"
}

// PreparedPublish is a signed publish transaction that has not necessarily been
// sent yet, held so that RETRIES RESEND THE SAME BYTES.
//
// This is what makes a retry safe. Building a fresh transaction per attempt
// takes a fresh pending nonce and therefore produces a DIFFERENT, equally valid
// transaction: both mine, and the workload is published twice.
// TestResendWithoutReconcilingPublishesTwice demonstrates that on a real node.
//
// Querying the contract before resending does not close the window on its own.
// While the first attempt is still pending it has not reached the contract yet,
// so the query says "absent" and a naive caller sends a second one anyway.
// Resending identical bytes is idempotent at the node, keeps the hash stable,
// and lets the receipt and the contract reconcile the same attempt.
//
// A prepared transaction does not survive a restart. Nothing here persists it,
// so exactly-once does not hold across a crash; the operator compensates by
// querying the contract before publishing anything. That limitation is real and
// is documented rather than hidden.
type PreparedPublish struct {
	// TxHash is known from the moment of signing, before any send.
	TxHash common.Hash

	tx *ethtypes.Transaction
}

// PublishOutcome is what actually became of a submitted transaction.
//
// There are three, not two, because "we do not know" is a real answer and
// collapsing it into failure is what causes duplicate publications.
type PublishOutcome int

const (
	// OutcomeUnknown means the transaction was not observed in a block within
	// the timeout. It is neither success nor failure: it may still land, so the
	// same prepared transaction should be retried rather than a new one built.
	OutcomeUnknown PublishOutcome = iota
	// OutcomeMinedSuccess means a receipt was retrieved with status 1. Mined,
	// not finalized: a reorg can still undo it.
	OutcomeMinedSuccess
	// OutcomeReverted means a receipt was retrieved with status 0. The
	// transaction definitively did not take effect, so the attempt can be
	// discarded and a fresh one prepared.
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

// Prepare builds and signs a publish transaction without sending it.
//
// Every failure here is unambiguous -- bad parameters, no key, a failed nonce
// or gas lookup -- so they are ordinary errors. Uncertainty begins only once a
// signed transaction exists.
//
// Prepare exactly once per desired revision. Preparing again allocates another
// nonce and re-introduces the duplicate-publication hazard.
func (c *ClientV2) Prepare(
	ctx context.Context,
	workloadID [32]byte,
	hashVersion uint16,
	configHash [32]byte,
	incarnation [32]byte,
	signature []byte,
	fingerprint [32]byte,
) (*PreparedPublish, error) {
	if c.auth == nil {
		return nil, fmt.Errorf("chain: client is read-only; no signing key configured")
	}
	if hashVersion == 0 {
		return nil, fmt.Errorf("chain: hash version 0 is not a valid protocol version")
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("chain: refusing to publish an empty signature")
	}

	opts := *c.auth
	opts.Context = ctx
	opts.NoSend = true
	tx, err := c.contract.Transact(&opts, "publish",
		workloadID, hashVersion, configHash, incarnation, signature, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("chain: build publish tx: %w", err)
	}
	return &PreparedPublish{TxHash: tx.Hash(), tx: tx}, nil
}

// SendResult reports what a dispatch attempt achieved.
//
// Outcome decides state. Cause never does: it is diagnosis only, kept so a
// sustained RPC outage shows up in logs, metrics and readiness instead of
// disappearing into an unexplained stream of unknowns. Reading Cause as failure
// would undo the entire point of the three-outcome model.
type SendResult struct {
	Outcome SubmitOutcome
	// Cause is the transport error, when there was one. A non-nil Cause does
	// NOT mean the node lacks the transaction.
	Cause error
}

// Send dispatches a prepared transaction. Sending the same PreparedPublish more
// than once is safe: the bytes are identical, so the node either accepts it or
// recognises it, and no second nonce is consumed.
//
// The error return is for unambiguous programming faults -- a nil or unsigned
// PreparedPublish, or a client with no connection -- where we know for certain
// nothing was sent. Uncertainty begins only once SendTransaction has been
// attempted; folding these cases into SubmitUnknown would hide a bug behind a
// state the caller is designed to tolerate.
func (c *ClientV2) Send(ctx context.Context, p *PreparedPublish) (SendResult, error) {
	if p == nil || p.tx == nil {
		return SendResult{}, fmt.Errorf("chain: send called with no prepared transaction")
	}
	if c.ec == nil {
		return SendResult{}, fmt.Errorf("chain: client has no connection")
	}
	if err := c.ec.SendTransaction(ctx, p.tx); err != nil {
		// Possibly delivered. Only the chain can settle it.
		return SendResult{Outcome: SubmitUnknown, Cause: err}, nil
	}
	return SendResult{Outcome: SubmitAccepted}, nil
}

// Hash returns the transaction hash, known from the moment of signing.
func (p *PreparedPublish) Hash() string {
	if p == nil {
		return ""
	}
	return p.TxHash.Hex()
}

// Wait blocks until the prepared transaction is mined, the timeout elapses, or
// the context is cancelled.
//
// Cancellation yields OutcomeUnknown, so a shutdown is never recorded as a
// failed publication.
func (c *ClientV2) Wait(ctx context.Context, p *PreparedPublish) PublishResult {
	res := PublishResult{Outcome: OutcomeUnknown}
	if p == nil || p.tx == nil {
		return res
	}
	res.TxHash = p.TxHash.Hex()

	waitCtx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	rcpt, err := bind.WaitMined(waitCtx, c.ec, p.tx)
	if err != nil {
		return res
	}

	res.BlockNumber = rcpt.BlockNumber.Uint64()
	res.GasUsed = rcpt.GasUsed
	if rcpt.Status == ethtypes.ReceiptStatusSuccessful {
		res.Outcome = OutcomeMinedSuccess
	} else {
		res.Outcome = OutcomeReverted
	}
	return res
}

// PublishAndWait is Prepare, Send and Wait in one call, for callers with no
// retry loop of their own. A caller that retries must keep the PreparedPublish
// and resend it rather than calling this again.
func (c *ClientV2) PublishAndWait(
	ctx context.Context,
	workloadID [32]byte,
	hashVersion uint16,
	configHash [32]byte,
	incarnation [32]byte,
	signature []byte,
	fingerprint [32]byte,
) (PublishResult, error) {
	p, err := c.Prepare(ctx, workloadID, hashVersion, configHash, incarnation, signature, fingerprint)
	if err != nil {
		return PublishResult{}, err
	}
	sent, err := c.Send(ctx, p)
	if err != nil {
		return PublishResult{}, err
	}
	if sent.Outcome == SubmitUnknown {
		// SHORTCUT, and only acceptable in this helper: return rather than
		// burn the timeout waiting on a hash the node may never have seen.
		//
		// A retry loop must NOT copy this. "Already known" also reports
		// unknown, and in that case the transaction is at the node and will
		// mine, so a state machine has to Wait or reconcile rather than
		// assume nothing happened.
		return PublishResult{TxHash: p.TxHash.Hex(), Outcome: OutcomeUnknown}, nil
	}
	return c.Wait(ctx, p), nil
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
