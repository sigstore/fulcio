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

package tinkca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

func TestNewTinkCA(t *testing.T) {
	aeskh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("error creating AEAD key handle: %v", err)
	}
	a, err := aead.New(aeskh)
	if err != nil {
		t.Fatalf("error creating AEAD key: %v", err)
	}

	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("error creating ECDSA key handle: %v", err)
	}
	khsigner, err := KeyHandleToSigner(kh)
	if err != nil {
		t.Fatalf("error converting ECDSA key handle to signer: %v", err)
	}

	rootCert, _ := test.GenerateRootCAFromSigner(khsigner)
	chain := []*x509.Certificate{rootCert}
	pemChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatalf("error marshalling cert chain: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	err = os.WriteFile(certPath, pemChain, 0600)
	if err != nil {
		t.Fatalf("error writing pem chain: %v", err)
	}

	keysetPath := filepath.Join(dir, "keyset.json.enc")
	f, err := os.Create(keysetPath)
	if err != nil {
		t.Fatalf("error creating file: %v", err)
	}
	defer f.Close()
	jsonWriter := keyset.NewJSONWriter(f)
	if err := kh.Write(jsonWriter, a); err != nil {
		t.Fatalf("error writing enc keyset: %v", err)
	}

	ca, err := NewTinkCAFromHandle(context.TODO(), keysetPath, certPath, a)
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
	certs, signer := ca.(*tinkCA).GetSignerWithChain()
	if err := cryptoutils.EqualKeys(signer.Public(), khsigner.Public()); err != nil {
		t.Fatalf("keys between CA and signer do not match: %v", err)
	}
	if !reflect.DeepEqual(certs, []*x509.Certificate{rootCert}) {
		t.Fatalf("expected certificate chains to match")
	}

	// Failure: Mismatch between signer and certificate key
	otherRootCert, _, _ := test.GenerateRootCA()
	pemChain, err = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{otherRootCert})
	if err != nil {
		t.Fatalf("error marshalling cert chain: %v", err)
	}
	err = os.WriteFile(certPath, pemChain, 0600)
	if err != nil {
		t.Fatalf("error writing pem chain: %v", err)
	}
	_, err = NewTinkCAFromHandle(context.TODO(), keysetPath, certPath, a)
	if err == nil || !strings.Contains(err.Error(), "ecdsa public keys are not equal") {
		t.Fatalf("expected error with mismatched public keys, got %v", err)
	}

	// Failure: Invalid certificate chain
	pemChain, err = cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, otherRootCert})
	if err != nil {
		t.Fatalf("error marshalling cert chain: %v", err)
	}
	err = os.WriteFile(certPath, pemChain, 0600)
	if err != nil {
		t.Fatalf("error writing pem chain: %v", err)
	}
	_, err = NewTinkCAFromHandle(context.TODO(), keysetPath, certPath, a)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("expected error with invalid certificate chain, got %v", err)
	}

	// Failure: Unable to decrypt keyset
	aeskh1, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("error creating AEAD key handle: %v", err)
	}
	a1, err := aead.New(aeskh1)
	if err != nil {
		t.Fatalf("error creating AEAD key: %v", err)
	}
	_, err = NewTinkCAFromHandle(context.TODO(), keysetPath, certPath, a1)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("expected error decrypting keyset, got %v", err)
	}
}
