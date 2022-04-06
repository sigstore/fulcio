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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type IntermediateCA struct {
	sync.RWMutex

	// certs is a chain of certificates from intermediate to root
	Certs  []*x509.Certificate
	Signer crypto.Signer
}

func (ica *IntermediateCA) CreatePrecertificate(ctx context.Context, challenge *challenges.ChallengeResult) (*ca.CodeSigningPreCertificate, error) {
	cert, err := x509ca.MakeX509(challenge)
	if err != nil {
		return nil, err
	}

	certChain, privateKey := ica.getX509KeyPair()

	// Append poison extension
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
		Critical: true,
		Value:    asn1.NullBytes,
	})

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, certChain[0], challenge.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	csc, err := ca.CreateCSCFromDER(challenge, finalCertBytes, certChain)
	if err != nil {
		return nil, err
	}

	return &ca.CodeSigningPreCertificate{
		Subject:    csc.Subject,
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
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
		Value: extBytes,
	}, nil
}

func (ica *IntermediateCA) IssueFinalCertificate(ctx context.Context, precert *ca.CodeSigningPreCertificate, sct *ct.SignedCertificateTimestamp) (*ca.CodeSigningCertificate, error) {
	// remove poison extension from precertificate.
	var exts []pkix.Extension
	for _, ext := range precert.PreCert.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
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
	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, precert.CertChain[0], precert.PreCert.PublicKey, precert.PrivateKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(precert.Subject, finalCertBytes, precert.CertChain)
}

func (ica *IntermediateCA) CreateCertificate(ctx context.Context, challenge *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	cert, err := x509ca.MakeX509(challenge)
	if err != nil {
		return nil, err
	}

	certChain, privateKey := ica.getX509KeyPair()

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, certChain[0], challenge.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(challenge, finalCertBytes, certChain)
}

func (ica *IntermediateCA) Root(ctx context.Context) ([]byte, error) {
	ica.RLock()
	defer ica.RUnlock()

	return cryptoutils.MarshalCertificatesToPEM(ica.Certs)
}

func (ica *IntermediateCA) getX509KeyPair() ([]*x509.Certificate, crypto.Signer) {
	ica.RLock()
	defer ica.RUnlock()

	return ica.Certs, ica.Signer
}

func VerifyCertChain(certs []*x509.Certificate, signer crypto.Signer) error {
	if len(certs) == 0 {
		return errors.New("certificate chain must contain at least one certificate")
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	if len(certs) > 1 {
		for _, intermediate := range certs[1 : len(certs)-1] {
			intermediates.AddCert(intermediate)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}

	if !certs[0].IsCA {
		return errors.New("certificate is not a CA")
	}

	// If using an intermediate, verify that code signing extended key
	// usage is set to satify extended key usage chainging
	if len(certs) > 1 {
		var hasExtKeyUsageCodeSigning bool
		for _, extKeyUsage := range certs[0].ExtKeyUsage {
			if extKeyUsage == x509.ExtKeyUsageCodeSigning {
				hasExtKeyUsageCodeSigning = true
				break
			}
		}
		if !hasExtKeyUsageCodeSigning {
			return errors.New(`certificate must have extended key usage code signing set to sign code signing certificates`)
		}
	}

	if err := cryptoutils.EqualKeys(certs[0].PublicKey, signer.Public()); err != nil {
		return err
	}

	if err := cryptoutils.ValidatePubKey(signer.Public()); err != nil {
		return err
	}

	return nil
}
