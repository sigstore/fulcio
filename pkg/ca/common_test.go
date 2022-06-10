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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/signature"
)

// cannot use ChallengeResult due to import cycle
type testPrincipal struct {
}

func (t *testPrincipal) Name(_ context.Context) string {
	return "test"
}
func (t *testPrincipal) Embed(_ context.Context, cert *x509.Certificate) error {
	cert.EmailAddresses = []string{"test@example.com"}
	return nil
}

func TestMakeX509(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	cert, err := MakeX509(context.TODO(), &testPrincipal{}, key.Public())
	if err != nil {
		t.Fatalf("unexpected error calling MakeX509: %v", err)
	}
	if cert.SerialNumber == nil {
		t.Fatalf("expected serial number")
	}
	if cert.NotAfter.Sub(cert.NotBefore) < time.Minute*10 {
		t.Fatalf("expected CA to have 10 minute lifetime, got %v", cert.NotAfter.Sub(cert.NotBefore))
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Fatalf("expected subject key ID")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("expected code signing extended key usage, got %v", cert.ExtKeyUsage)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected digital signature key usage, got %v", cert.KeyUsage)
	}
	// test that Embed is called
	if len(cert.EmailAddresses) != 1 {
		t.Fatalf("expected email in subject alt name, got %v", cert.EmailAddresses)
	}
}

func TestVerifyCertChain(t *testing.T) {
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
