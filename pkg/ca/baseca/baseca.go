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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/identity"
)

var (
	// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	// OIDExtensionCTSCT is defined in RFC 6962 s3.3.
	OIDExtensionCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

type BaseCA struct {
	// contains the chain of certificates and signer
	ca.SignerWithChain
}

func (bca *BaseCA) CreatePrecertificate(ctx context.Context, principal identity.Principal, publicKey crypto.PublicKey) (*ca.CodeSigningPreCertificate, error) {
	cert, err := ca.MakeX509(ctx, principal, publicKey)
	if err != nil {
		return nil, err
	}

	certChain, privateKey := bca.GetSignerWithChain()

	// Append poison extension
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
		Id:       OIDExtensionCTPoison,
		Critical: true,
		Value:    asn1.NullBytes,
	})

	cert.SignatureAlgorithm, err = ca.ToSignatureAlgorithm(privateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, certChain[0], publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	csc, err := ca.CreateCSCFromDER(finalCertBytes, certChain)
	if err != nil {
		return nil, err
	}

	return &ca.CodeSigningPreCertificate{
		PreCert:    csc.FinalCertificate,
		CertChain:  csc.FinalChain,
		PrivateKey: privateKey,
	}, nil
}

// From https://github.com/letsencrypt/boulder/blob/54b697d51b9f63cfd6055577cd317d4096aeab08/issuance/issuance.go#L497
func generateSCTListExt(scts []ct.SignedCertificateTimestamp) (pkix.Extension, error) {
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range scts {
		sctBytes, err := cttls.Marshal(sct)
		if err != nil {
			return pkix.Extension{}, err
		}
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sctBytes})
	}
	listBytes, err := cttls.Marshal(list)
	if err != nil {
		return pkix.Extension{}, err
	}
	extBytes, err := asn1.Marshal(listBytes)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    OIDExtensionCTSCT,
		Value: extBytes,
	}, nil
}

func (bca *BaseCA) IssueFinalCertificate(_ context.Context, precert *ca.CodeSigningPreCertificate, sct *ct.SignedCertificateTimestamp) (*ca.CodeSigningCertificate, error) {
	// remove poison extension from precertificate.
	var exts []pkix.Extension
	for _, ext := range precert.PreCert.Extensions {
		if !ext.Id.Equal(OIDExtensionCTPoison) {
			exts = append(exts, ext)
		}
	}
	// append SCT extension. Supports multiple SCTs, but Fulcio only writes to one log currently.
	sctExt, err := generateSCTListExt([]ct.SignedCertificateTimestamp{*sct})
	if err != nil {
		return nil, err
	}
	exts = append(exts, sctExt)

	cert := precert.PreCert
	cert.ExtraExtensions = exts

	cert.SignatureAlgorithm, err = ca.ToSignatureAlgorithm(precert.PrivateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, precert.CertChain[0], precert.PreCert.PublicKey, precert.PrivateKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(finalCertBytes, precert.CertChain)
}

func (bca *BaseCA) CreateCertificate(ctx context.Context, principal identity.Principal, publicKey crypto.PublicKey) (*ca.CodeSigningCertificate, error) {
	cert, err := ca.MakeX509(ctx, principal, publicKey)
	if err != nil {
		return nil, err
	}

	certChain, privateKey := bca.GetSignerWithChain()

	cert.SignatureAlgorithm, err = ca.ToSignatureAlgorithm(privateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, certChain[0], publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(finalCertBytes, certChain)
}

func (bca *BaseCA) TrustBundle(_ context.Context) ([][]*x509.Certificate, error) {
	certs, _ := bca.GetSignerWithChain()
	return [][]*x509.Certificate{certs}, nil
}

func (bca *BaseCA) Close() error {
	return nil
}
