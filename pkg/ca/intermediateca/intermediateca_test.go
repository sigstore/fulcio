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

package intermediateca

import (
	"context"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestIntermediateCARoot(t *testing.T) {
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}
	pemChain, err := cryptoutils.MarshalCertificatesToPEM(certChain)
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	ica := IntermediateCA{
		Certs:  certChain,
		Signer: signer,
	}

	rootBytes, err := ica.Root(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error reading root: %v", err)
	}

	if !reflect.DeepEqual(pemChain, rootBytes) {
		t.Fatal("expected cert chains to be equivalent")
	}
}

func TestIntermediateCAGetX509KeyPair(t *testing.T) {
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}

	ica := IntermediateCA{
		Certs:  certChain,
		Signer: signer,
	}

	foundCertChain, foundSigner := ica.getX509KeyPair()

	if !reflect.DeepEqual(certChain, foundCertChain) {
		t.Fatal("expected cert chains to be equivalent")
	}

	if err := cryptoutils.EqualKeys(signer.Public(), foundSigner.Public()); err != nil {
		t.Fatalf("expected keys to be equivalent, expected %v, got %v, error %v", signer.Public(), foundSigner.Public(), err)
	}
}

func TestIntermediateCAVerifyCertChain(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, subKey, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)

	err := VerifyCertChain([]*x509.Certificate{subCert, rootCert}, subKey)
	if err != nil {
		t.Fatalf("unexpected error verifying cert chain: %v", err)
	}

	// Handles single certifiacte in chain
	err = VerifyCertChain([]*x509.Certificate{rootCert}, rootKey)
	if err != nil {
		t.Fatalf("unexpected error verifying single cert chain: %v", err)
	}

	// Handles multiple intermediates
	subCert2, subKey2, _ := test.GenerateSubordinateCA(subCert, subKey)
	err = VerifyCertChain([]*x509.Certificate{subCert2, subCert, rootCert}, subKey2)
	if err != nil {
		t.Fatalf("unexpected error verifying cert chain: %v", err)
	}

	// Failure: Certificate is not a CA certificate
	err = VerifyCertChain([]*x509.Certificate{leafCert}, nil)
	if err == nil || !strings.Contains(err.Error(), "certificate is not a CA") {
		t.Fatalf("expected error with non-CA cert: %v", err)
	}

	// Failure: Certificate missing EKU
	// Note that the wrong EKU will be caught by x509.Verify
	invalidSubCert, invalidSubKey, _ := test.GenerateSubordinateCAWithoutEKU(rootCert, rootKey)
	err = VerifyCertChain([]*x509.Certificate{invalidSubCert, rootCert}, invalidSubKey)
	if err == nil || !strings.Contains(err.Error(), "certificate must have extended key usage code signing") {
		t.Fatalf("expected error verifying cert chain without EKU: %v", err)
	}

	// Failure: Invalid chain
	rootCert2, _, _ := test.GenerateRootCA()
	err = VerifyCertChain([]*x509.Certificate{subCert, rootCert2}, subKey)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("expected error verifying cert chain: %v", err)
	}

	// Failure: Different signer with different key
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("expected error generating signer: %v", err)
	}
	err = VerifyCertChain([]*x509.Certificate{subCert, rootCert}, signer)
	if err == nil || !strings.Contains(err.Error(), "public keys are not equal") {
		t.Fatalf("expected error verifying cert with mismatched public keys: %v", err)
	}

	// Failure: Weak key
	weakSubCert, weakSubKey, _ := test.GenerateWeakSubordinateCA(rootCert, rootKey)
	err = VerifyCertChain([]*x509.Certificate{weakSubCert, rootCert}, weakSubKey)
	if err == nil || !strings.Contains(err.Error(), "unsupported ec curve") {
		t.Fatalf("expected error verifying weak cert chain: %v", err)
	}

	// Failure: Empty chain
	err = VerifyCertChain([]*x509.Certificate{}, weakSubKey)
	if err == nil || !strings.Contains(err.Error(), "certificate chain must contain at least one certificate") {
		t.Fatalf("expected error verifying with empty chain: %v", err)
	}
}
