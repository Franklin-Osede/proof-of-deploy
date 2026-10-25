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

package publisher

import (
	"context"
	"fmt"

	"github.com/franklin1014/proof-of-deploy/internal/chain"
)

// ChainV2Client is the slice of chain.ClientV2 the adapter needs. Declared so
// the translation can be tested without a node.
type ChainV2Client interface {
	LatestAttestation(ctx context.Context, workloadID [32]byte) (chain.AttestationV2, error)
	Prepare(ctx context.Context, workloadID [32]byte, hashVersion uint16, configHash [32]byte,
		incarnation [32]byte, signature []byte, fingerprint [32]byte) (*chain.PreparedPublish, error)
	Send(ctx context.Context, p *chain.PreparedPublish) (chain.SendResult, error)
	Wait(ctx context.Context, p *chain.PreparedPublish) chain.PublishResult
}

// chainV2Adapter translates between the publisher's vocabulary and the chain
// client's. It adds no behaviour: every decision stays in PublisherV2, where it
// is tested.
type chainV2Adapter struct {
	c ChainV2Client
}

// NewChainV2 adapts a v2 chain client to the interface PublisherV2 drives.
func NewChainV2(c ChainV2Client) ChainV2 {
	return chainV2Adapter{c: c}
}

func (a chainV2Adapter) Latest(ctx context.Context, workloadID [32]byte) (OnChain, error) {
	att, err := a.c.LatestAttestation(ctx, workloadID)
	if err != nil {
		return OnChain{}, err
	}
	if !att.Exists {
		return OnChain{}, nil
	}
	return OnChain{
		Exists: true,
		Key: RevisionKey{
			Version:     att.HashVersion,
			ConfigHash:  att.ConfigHash,
			Incarnation: att.Incarnation,
			Fingerprint: att.SignerFingerprint,
		},
		Signature: att.Signature,
	}, nil
}

func (a chainV2Adapter) Prepare(ctx context.Context, workloadID [32]byte, key RevisionKey, signature []byte) (PreparedTx, error) {
	p, err := a.c.Prepare(ctx, workloadID, key.Version, key.ConfigHash, key.Incarnation, signature, key.Fingerprint)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (a chainV2Adapter) Send(ctx context.Context, p PreparedTx) (SendOutcome, error) {
	pp, err := prepared(p)
	if err != nil {
		return SendUnknown, err
	}
	res, err := a.c.Send(ctx, pp)
	if err != nil {
		return SendUnknown, err
	}
	if res.Outcome == chain.SubmitAccepted {
		return SendAccepted, nil
	}
	return SendUnknown, nil
}

func (a chainV2Adapter) Wait(ctx context.Context, p PreparedTx) (WaitOutcome, error) {
	pp, err := prepared(p)
	if err != nil {
		return WaitUnknown, err
	}
	switch a.c.Wait(ctx, pp).Outcome {
	case chain.OutcomeMinedSuccess:
		return WaitMinedSuccess, nil
	case chain.OutcomeReverted:
		return WaitReverted, nil
	default:
		return WaitUnknown, nil
	}
}

// prepared recovers the chain's own type. Anything else is a wiring fault: a
// handle from a different backend can never be sent by this one.
func prepared(p PreparedTx) (*chain.PreparedPublish, error) {
	pp, ok := p.(*chain.PreparedPublish)
	if !ok || pp == nil {
		return nil, fmt.Errorf("publisher: prepared transaction %T was not made by the v2 chain client", p)
	}
	return pp, nil
}
