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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/internal/ctl"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type nilPublicKeySigner struct{}

func (nilPublicKeySigner) Public() crypto.PublicKey { return nil }
func (nilPublicKeySigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestVerifySigner(t *testing.T) {
	t.Run("nil signer returns error", func(t *testing.T) {
		if err := verifySigner(nil); err == nil {
			t.Fatal("expected error for nil signer, got nil")
		}
	})

	t.Run("signer with nil public key returns error", func(t *testing.T) {
		if err := verifySigner(nilPublicKeySigner{}); err == nil {
			t.Fatal("expected error for nil public key, got nil")
		}
	})

	t.Run("valid signer returns nil", func(t *testing.T) {
		signer, _, err := signature.NewDefaultECDSASignerVerifier()
		if err != nil {
			t.Fatalf("unexpected error generating signer: %v", err)
		}
		if err := verifySigner(signer); err != nil {
			t.Fatalf("unexpected error for valid signer: %v", err)
		}
	})
}

func TestCreatePrecertificateNilSigner(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	bca := BaseCA{SignerWithChain: &ca.SignerCerts{Certs: certChain, Signer: nil}}
	_, err := bca.CreatePrecertificate(context.TODO(), testPrincipal{}, priv.Public())
	if err == nil || !strings.Contains(err.Error(), "CA signing key is unavailable") {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func TestCreateCertificateNilSigner(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCA()
	subCert, _, _ := test.GenerateSubordinateCA(rootCert, rootKey)
	certChain := []*x509.Certificate{subCert, rootCert}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	bca := BaseCA{SignerWithChain: &ca.SignerCerts{Certs: certChain, Signer: nil}}
	_, err := bca.CreateCertificate(context.TODO(), testPrincipal{}, priv.Public())
	if err == nil || !strings.Contains(err.Error(), "CA signing key is unavailable") {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

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

	testSCT := &ctl.SignedCertificateTimestamp{
		SCTVersion: ctl.V1,
		LogID:      [32]byte{1, 2, 3, 4},
		Timestamp:  0x0102030405060708,
		Extensions: []byte{0xaa, 0xbb},
		Signature: ctl.DigitallySigned{
			Algorithm: ctl.SignatureAndHashAlgorithm{Hash: ctl.SHA256, Signature: ctl.ECDSA},
			Signature: []byte{0x01, 0x02, 0x03, 0x04},
		},
	}
	csc, err := bca.IssueFinalCertificate(context.TODO(), precsc, testSCT)
	if err != nil {
		t.Fatalf("error issuing certificate: %v", err)
	}
	// verify will now work since poison extension is removed
	_, err = csc.FinalCertificate.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: subPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		t.Fatalf("unexpected error verifying final certificate: %v", err)
	}
	var sctExtValue []byte
	for _, ext := range csc.FinalCertificate.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
			if ext.Critical {
				t.Fatal("SCT extension must not be critical")
			}
			sctExtValue = ext.Value
		}
	}
	if len(sctExtValue) == 0 {
		t.Fatal("expected SCT extension to be in certificate")
	}
	// RFC 6962 s3.3: extension value is an ASN.1 OCTET STRING wrapping SignedCertificateTimestampList.
	var sctListBytes []byte
	rest, err := asn1.Unmarshal(sctExtValue, &sctListBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal SCT extension OCTET STRING: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes in SCT extension: %x", rest)
	}
	// Verify exact TLS wire layout:
	//   outer len (2) = 2 + 53 = 55 (0x0037)
	//   inner len (2) = 1(ver) + 32(logID) + 8(ts) + 2+2(exts) + 1+1+2+4(sig) = 53 (0x0035)
	if len(sctListBytes) != 57 {
		t.Fatalf("len(sctListBytes) = %d, want 57", len(sctListBytes))
	}
	if sctListBytes[0] != 0x00 || sctListBytes[1] != 0x37 || sctListBytes[2] != 0x00 || sctListBytes[3] != 0x35 {
		t.Fatalf("unexpected SCT list length prefixes: %x", sctListBytes[:4])
	}
	if sctListBytes[4] != 0x00 || sctListBytes[5] != 1 || sctListBytes[6] != 2 || sctListBytes[7] != 3 || sctListBytes[8] != 4 {
		t.Fatalf("unexpected SCT version/logID prefix: %x", sctListBytes[4:9])
	}
}
