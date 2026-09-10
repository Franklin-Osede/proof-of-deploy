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

package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMS can be made to lie in every way a real endpoint, a broken
// compatible implementation, or a repointed alias could.
type fakeKMS struct {
	key *ecdsa.PrivateKey

	pubDER    []byte
	keySpec   kmstypes.KeySpec
	keyUsage  kmstypes.KeyUsageType
	algos     []kmstypes.SigningAlgorithmSpec
	returnKey string
	getErr    error

	signErr        error
	signKeyID      string
	signAlgo       kmstypes.SigningAlgorithmSpec
	signWithKey    *ecdsa.PrivateKey // sign with a different key
	signOverDigest []byte            // sign something other than what was asked
	mutateSig      func([]byte) []byte

	lastSignKeyID string
	signCalls     int
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &fakeKMS{
		key: k, pubDER: der,
		keySpec:  kmstypes.KeySpecEccNistP256,
		keyUsage: kmstypes.KeyUsageTypeSignVerify,
		algos:    []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
	}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	id := f.returnKey
	if id == "" {
		id = *in.KeyId
	}
	return &kms.GetPublicKeyOutput{
		KeyId: &id, KeySpec: f.keySpec, KeyUsage: f.keyUsage,
		SigningAlgorithms: f.algos, PublicKey: f.pubDER,
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	f.lastSignKeyID = *in.KeyId
	if f.signErr != nil {
		return nil, f.signErr
	}

	key := f.key
	if f.signWithKey != nil {
		key = f.signWithKey
	}
	msg := in.Message
	if f.signOverDigest != nil {
		msg = f.signOverDigest
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, msg)
	if err != nil {
		return nil, err
	}
	if f.mutateSig != nil {
		sig = f.mutateSig(sig)
	}

	algo := f.signAlgo
	if algo == "" {
		algo = kmstypes.SigningAlgorithmSpecEcdsaSha256
	}
	id := f.signKeyID
	if id == "" {
		id = *in.KeyId
	}
	return &kms.SignOutput{Signature: sig, SigningAlgorithm: algo, KeyId: &id}, nil
}

func digest(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// --- construction -----------------------------------------------------------

func TestConstructionAcceptsAValidP256Key(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("rejected a valid key: %v", err)
	}
	if !bytes.Equal(s.PublicKeyDER(), f.pubDER) {
		t.Error("cached public key differs from what KMS returned")
	}
}

func TestConstructionRejectsUnsuitableKeys(t *testing.T) {
	rsaDER := func(t *testing.T) []byte {
		t.Helper()
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return der
	}
	p384DER := func(t *testing.T) []byte {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("p384: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return der
	}

	cases := map[string]func(t *testing.T, f *fakeKMS){
		"RSA key spec": func(_ *testing.T, f *fakeKMS) {
			f.keySpec = kmstypes.KeySpecRsa2048
		},
		"RSA key material behind a P-256 spec": func(t *testing.T, f *fakeKMS) {
			f.pubDER = rsaDER(t)
		},
		"another EC curve behind a P-256 spec": func(t *testing.T, f *fakeKMS) {
			// KeySpec and key material disagreeing means neither can be trusted.
			f.pubDER = p384DER(t)
		},
		"wrong key usage": func(_ *testing.T, f *fakeKMS) {
			f.keyUsage = kmstypes.KeyUsageTypeEncryptDecrypt
		},
		"algorithm not offered": func(_ *testing.T, f *fakeKMS) {
			f.algos = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha384}
		},
		"no algorithms at all": func(_ *testing.T, f *fakeKMS) {
			f.algos = nil
		},
		"empty public key": func(_ *testing.T, f *fakeKMS) {
			f.pubDER = nil
		},
		"corrupt DER": func(_ *testing.T, f *fakeKMS) {
			f.pubDER = []byte{0x30, 0x59, 0x01, 0x02, 0x03}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeKMS(t)
			mutate(t, f)
			if _, err := newWithClient(context.Background(), f, "alias/pod"); err == nil {
				t.Fatal("accepted an unsuitable key")
			}
		})
	}
}

func TestConstructionRejectsAnEmptyKeyID(t *testing.T) {
	for _, id := range []string{"", "   "} {
		if _, err := newWithClient(context.Background(), newFakeKMS(t), id); err == nil {
			t.Errorf("accepted key id %q", id)
		}
	}
}

func TestConstructionPropagatesKMSErrors(t *testing.T) {
	f := newFakeKMS(t)
	f.getErr = errors.New("AccessDeniedException: not authorized")
	_, err := newWithClient(context.Background(), f, "alias/pod")
	if err == nil {
		t.Fatal("a KMS failure was swallowed")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("the cause was lost: %v", err)
	}
}

// --- aliases ----------------------------------------------------------------

// TestAliasIsResolvedAndSignedByCanonicalID is the window this closes.
//
// Configuration may name an alias. If it does and the alias is repointed after
// startup, GetPublicKey has already cached the old key while Sign would reach
// the new one: the record would carry the old fingerprint beside a signature
// from a different key, and could never verify.
func TestAliasIsResolvedAndSignedByCanonicalID(t *testing.T) {
	const (
		alias     = "alias/proof-of-deploy"
		canonical = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	)
	f := newFakeKMS(t)
	f.returnKey = canonical

	s, err := newWithClient(context.Background(), f, alias)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if s.KeyID() != canonical {
		t.Errorf("KeyID() = %q, want the canonical id", s.KeyID())
	}
	if s.ConfiguredKeyID() != alias {
		t.Errorf("ConfiguredKeyID() = %q, want the alias", s.ConfiguredKeyID())
	}

	if _, err := s.SignDigest(context.Background(), digest("x")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if f.lastSignKeyID != canonical {
		t.Errorf("signed with %q; an alias here is exactly what lets a repoint slip through", f.lastSignKeyID)
	}
}

// --- signing responses ------------------------------------------------------

func TestSignRejectsInconsistentResponses(t *testing.T) {
	cases := map[string]func(f *fakeKMS){
		"empty signature": func(f *fakeKMS) {
			f.mutateSig = func([]byte) []byte { return nil }
		},
		"truncated signature": func(f *fakeKMS) {
			f.mutateSig = func(b []byte) []byte { return b[:len(b)-4] }
		},
		"signature from another key": func(f *fakeKMS) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			f.signWithKey = k
		},
		"signature over another digest": func(f *fakeKMS) {
			d := digest("something else")
			f.signOverDigest = d[:]
		},
		"unexpected algorithm": func(f *fakeKMS) {
			f.signAlgo = kmstypes.SigningAlgorithmSpecEcdsaSha384
		},
		"unexpected key id": func(f *fakeKMS) {
			f.signKeyID = "arn:aws:kms:eu-west-1:111122223333:key/somebody-else"
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeKMS(t)
			s, err := newWithClient(context.Background(), f, "alias/pod")
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			mutate(f)
			if _, err := s.SignDigest(context.Background(), digest("payload")); err == nil {
				t.Fatalf("accepted a response with %s", name)
			}
		})
	}
}

func TestSignReturnsAVerifiableSignature(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	d := digest("payload")
	sig, err := s.SignDigest(context.Background(), d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&f.key.PublicKey, d[:], sig) {
		t.Fatal("the returned signature does not verify")
	}
}

func TestSignPropagatesErrorsWithoutLeakingMaterial(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	f.signErr = errors.New("ThrottlingException: rate exceeded")
	_, err = s.SignDigest(context.Background(), digest("payload"))
	if err == nil {
		t.Fatal("a KMS failure was swallowed")
	}
	if !strings.Contains(err.Error(), "rate exceeded") {
		t.Errorf("the cause was lost: %v", err)
	}
}

func TestSignRespectsContextCancellation(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.signErr = ctx.Err()
	if _, err := s.SignDigest(ctx, digest("payload")); err == nil {
		t.Fatal("a cancelled sign reported success")
	}
}

// --- defensive copies -------------------------------------------------------

func TestPublicKeyDERIsACopy(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	got := s.PublicKeyDER()
	original := append([]byte(nil), got...)
	for i := range got {
		got[i] ^= 0xff
	}
	if !bytes.Equal(s.PublicKeyDER(), original) {
		t.Fatal("mutating the returned slice changed what the signer believes its key to be")
	}
}

// TestConstructionCopiesTheResponseBuffer pins that the signer does not alias
// memory owned by the KMS client. A response buffer may be reused.
func TestConstructionCopiesTheResponseBuffer(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	before := s.PublicKeyDER()

	for i := range f.pubDER {
		f.pubDER[i] ^= 0xff
	}
	if !bytes.Equal(s.PublicKeyDER(), before) {
		t.Fatal("the signer aliases the buffer KMS returned")
	}
}

func TestSignatureIsCopiedFromTheResponse(t *testing.T) {
	f := newFakeKMS(t)
	s, err := newWithClient(context.Background(), f, "alias/pod")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	d := digest("payload")

	var handedOut []byte
	f.mutateSig = func(b []byte) []byte {
		handedOut = b
		return b
	}
	sig, err := s.SignDigest(context.Background(), d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for i := range handedOut {
		handedOut[i] ^= 0xff
	}
	if !ecdsa.VerifyASN1(&f.key.PublicKey, d[:], sig) {
		t.Fatal("the returned signature aliases the response buffer")
	}
}
