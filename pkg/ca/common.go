// Copyright 2021 The Sigstore Authors.
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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func MakeX509(ctx context.Context, principal identity.Principal, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	serialNumber, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	skid, err := cryptoutils.SKID(publicKey)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * 10),
		SubjectKeyId: skid,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	err = principal.Embed(ctx, cert)
	if err != nil {
		return nil, ValidationError(err)
	}

	return cert, nil
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
