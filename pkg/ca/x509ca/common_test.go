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

package x509ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
	"time"
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

func TestRootAndCreateCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating key: %v", err)
	}
	cert, err := MakeX509(context.TODO(), &testPrincipal{}, key.Public())
	if err != nil {
		t.Fatalf("unexpected error calling MakeX509: %v", err)
	}
	// sign certificate to populate with expected values
	caBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatalf("unexpected error signing certificate: %v", err)
	}
	ca := &X509CA{
		PrivKey: key,
	}
	ca.RootCA, err = x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("unexpected error parsing certificate, got %v", err)
	}

	pemRoot, err := ca.Root(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error generating root: %v", err)
	}
	block, rest := pem.Decode(pemRoot)
	if len(rest) > 0 {
		t.Fatalf("expected no additional PEM blocks")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE type, got %s", block.Type)
	}
	if !reflect.DeepEqual(ca.RootCA.Raw, block.Bytes) {
		t.Fatalf("raw certificates were not equal")
	}

	// create a certificate that chains up to this CA
	csc, err := ca.CreateCertificate(context.TODO(), &testPrincipal{}, key.Public())
	if err != nil {
		t.Fatalf("unexpected error creating certificate: %v", err)
	}
	if csc.FinalCertificate == nil {
		t.Fatalf("expected certificate in structure")
	}
	if len(csc.FinalChain) != 1 {
		t.Fatalf("expected 1 certificate in chain, got %d", len(csc.FinalChain))
	}
}
