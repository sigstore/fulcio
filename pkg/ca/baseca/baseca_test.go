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

package baseca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestBaseCARoot(t *testing.T) {
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}

	bca := BaseCA{
		SignerWithChain: &ca.SignerCerts{Certs: certChain, Signer: signer},
	}

	rootChains, err := bca.TrustBundle(context.TODO())
	if err != nil {
		t.Fatalf("unexpected error reading root: %v", err)
	}
	if len(rootChains) != 1 {
		t.Fatalf("unexpected number of chains: %d", len(rootChains))
	}

	if !reflect.DeepEqual(certChain, rootChains[0]) {
		t.Fatal("expected cert chains to be equivalent")
	}
}

func TestBaseCAGetSignerWithChain(t *testing.T) {
	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}

	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}

	bca := BaseCA{
		SignerWithChain: &ca.SignerCerts{Certs: certChain, Signer: signer},
	}

	foundCertChain, foundSigner := bca.GetSignerWithChain()

	if !reflect.DeepEqual(certChain, foundCertChain) {
		t.Fatal("expected cert chains to be equivalent")
	}

	if err := cryptoutils.EqualKeys(signer.Public(), foundSigner.Public()); err != nil {
		t.Fatalf("expected keys to be equivalent, expected %v, got %v, error %v", signer.Public(), foundSigner.Public(), err)
	}
}

type testPrincipal struct{}

func (tp testPrincipal) Name(context.Context) string {
	return "doesntmatter"
}

func (tp testPrincipal) Embed(_ context.Context, cert *x509.Certificate) (err error) {
	cert.EmailAddresses = []string{"alice@example.com"}
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: "example.com",
	}.Render()
	return
}

func TestCreatePrecertificateAndIssueFinalCertificate(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, subKey, _ := test.GenerateSubordinateCA(rootCert, rootKey)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certChain := []*x509.Certificate{subCert, rootCert}

	bca := BaseCA{
		SignerWithChain: &ca.SignerCerts{Certs: certChain, Signer: subKey},
	}

	precsc, err := bca.CreatePrecertificate(context.TODO(), testPrincipal{}, priv.Public())

	if err != nil {
		t.Fatalf("error generating precertificate: %v", err)
	}
	if !subKey.Equal(precsc.PrivateKey) {
		t.Fatal("subordinate private keys are not equal")
	}
	if !reflect.DeepEqual(certChain, precsc.CertChain) {
		t.Fatal("certificate chains are not equal")
	}

	// check cert doesn't verify due to poison extension
	rootPool := x509.NewCertPool()
	rootPool.AddCert(precsc.CertChain[1])
	subPool := x509.NewCertPool()
	subPool.AddCert(precsc.CertChain[0])
	_, err = precsc.PreCert.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: subPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err == nil || err.Error() != "x509: unhandled critical extension" {
		t.Fatalf("expected unhandled critical ext error, got %v", err)
	}

	csc, err := bca.IssueFinalCertificate(context.TODO(), precsc, &ct.SignedCertificateTimestamp{SCTVersion: 1})
	if err != nil {
		t.Fatalf("error issuing certificate: %v", err)
	}
	// verify will now work since poison extension is removed
	_, err = csc.FinalCertificate.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: subPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		t.Fatalf("unexpected error verifying final certificate: %v", err)
	}
	var foundSct bool
	for _, ext := range csc.FinalCertificate.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
			foundSct = true
		}
	}
	if !foundSct {
		t.Fatal("expected SCT extension to be in certificate")
	}
}
