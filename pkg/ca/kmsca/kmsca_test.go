// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package kmsca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewKMSCA(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, subKey, _ := test.GenerateSubordinateCA(rootCert, rootKey)

	chain := []*x509.Certificate{subCert, rootCert}

	ca, err := NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", chain)
	if err != nil {
		t.Fatalf("unexpected error creating KMS CA: %v", err)
	}

	// Expect certificate chain from Root matches provided certificate chain
	rootChains, err := ca.TrustBundle(context.TODO())
	if err != nil {
		t.Fatalf("error fetching root: %v", err)
	}
	if len(rootChains) != 1 {
		t.Fatalf("unexpected number of chains: %d", len(rootChains))
	}
	if !reflect.DeepEqual(rootChains[0], chain) {
		t.Fatalf("cert chains do not match")
	}

	// Expect signer and certificate's public keys match
	ica := ca.(*kmsCA)
	certs, signer := ica.GetSignerWithChain()
	if err := cryptoutils.EqualKeys(signer.Public(), subKey.Public()); err != nil {
		t.Fatalf("keys between CA and signer do not match: %v", err)
	}
	if !reflect.DeepEqual(certs, []*x509.Certificate{subCert, rootCert}) {
		t.Fatalf("expected certificate chains to match")
	}

	// Failure: Mismatch between signer and certificate key
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, otherPriv), "fakekms://key", chain)
	if err == nil || !strings.Contains(err.Error(), "ecdsa public keys are not equal") {
		t.Fatalf("expected error with mismatched public keys, got %v", err)
	}

	// Failure: Invalid certificate chain
	otherRootCert, _, _ := test.GenerateRootCA()
	_, err = NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", []*x509.Certificate{subCert, otherRootCert})
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("expected error with invalid certificate chain, got %v", err)
	}
}

type failingPublicKeySigner struct {
	errFunc func(error)
}

func (s failingPublicKeySigner) Public() crypto.PublicKey {
	if s.errFunc != nil {
		s.errFunc(errors.New("kms public key fetch failed"))
	}
	return nil
}

func (failingPublicKeySigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

type failingSignerVerifier struct {
	*fake.SignerVerifier
}

func (f failingSignerVerifier) CryptoSigner(_ context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	return failingPublicKeySigner{errFunc: errFunc}, crypto.SHA256, nil
}

func TestNewKMSCALogsPublicKeyError(t *testing.T) {
	kms.AddProvider("testkms://", func(ctx context.Context, _ string, hf crypto.Hash, _ ...signature.RPCOption) (kms.SignerVerifier, error) {
		sv, err := fake.LoadSignerVerifier(ctx, hf)
		if err != nil {
			return nil, err
		}
		return failingSignerVerifier{SignerVerifier: sv}, nil
	})

	core, logs := observer.New(zap.ErrorLevel)
	origLogger := log.Logger
	log.Logger = zap.New(core).Sugar()
	t.Cleanup(func() { log.Logger = origLogger })

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	chain := []*x509.Certificate{subCert, rootCert}

	// NewKMSCA will fail (VerifyCertChain can't compare keys), but the error
	// callback should have logged the underlying public-key fetch failure.
	_, _ = NewKMSCA(context.TODO(), "testkms://key", chain)

	entries := logs.FilterMessageSnippet("error fetching public key from KMS signer").All()
	if len(entries) == 0 {
		t.Fatalf("expected an error log for the failed public key fetch, got none; all logs: %v", logs.All())
	}
	if !strings.Contains(entries[0].Message, "testkms://key") {
		t.Fatalf("expected log to contain the KMS key reference, got: %q", entries[0].Message)
	}
}

func TestNewKMSCAMLDSA(t *testing.T) {
	rootKey, _ := mldsa.GenerateKey(mldsa.MLDSA87())
	rootCert, _ := test.GenerateRootCAFromSigner(rootKey)
	subKey, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	subCert, _ := test.GenerateSubordinateCAFromSigner(rootCert, rootKey, subKey)

	chain := []*x509.Certificate{subCert, rootCert}

	ca, err := NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", chain)
	if err != nil {
		t.Fatalf("unexpected error creating KMS CA: %v", err)
	}

	_, signer := ca.(*kmsCA).GetSignerWithChain()
	if err := cryptoutils.EqualKeys(signer.Public(), subKey.Public()); err != nil {
		t.Fatalf("keys between CA and signer do not match: %v", err)
	}

	// Failure: ML-DSA key with a classical certificate chain
	classicalRootCert, classicalRootKey, _ := test.GenerateRootCA()
	mixedSubCert, _ := test.GenerateSubordinateCAFromSigner(classicalRootCert, classicalRootKey, subKey)
	_, err = NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", []*x509.Certificate{mixedSubCert, classicalRootCert})
	if err == nil || !strings.Contains(err.Error(), "must not mix ML-DSA and non-ML-DSA") {
		t.Fatalf("expected error with mixed certificate chain, got %v", err)
	}
}
