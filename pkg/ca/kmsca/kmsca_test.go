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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
)

func TestNewKMSCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, subKey, _ := test.GenerateSubordinateCA(rootCert, rootKey)

	chain := []*x509.Certificate{subCert, rootCert}
	pemChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatalf("error marshalling cert chain: %v", err)
	}
	err = os.WriteFile(certPath, pemChain, 0600)
	if err != nil {
		t.Fatalf("error writing pem chain: %v", err)
	}

	ca, err := NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", certPath)
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
		t.Fatal("cert chains do not match")
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
	_, err = NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, otherPriv), "fakekms://key", certPath)
	if err == nil || !strings.Contains(err.Error(), "ecdsa public keys are not equal") {
		t.Fatalf("expected error with mismatched public keys, got %v", err)
	}

	// Failure: Invalid certificate chain
	otherRootCert, _, _ := test.GenerateRootCA()
	pemChain, err = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, otherRootCert})
	if err != nil {
		t.Fatalf("error marshalling cert chain: %v", err)
	}
	err = os.WriteFile(certPath, pemChain, 0600)
	if err != nil {
		t.Fatalf("error writing pem chain: %v", err)
	}
	_, err = NewKMSCA(context.WithValue(context.TODO(), fake.KmsCtxKey{}, subKey), "fakekms://key", certPath)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("expected error with invalid certificate chain, got %v", err)
	}
}
