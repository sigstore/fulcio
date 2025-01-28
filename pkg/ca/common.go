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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
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

	return cryptoutils.ValidatePubKey(signer.Public())
}

// ToSignatureAlgorithm returns the x509.SignatureAlgorithm for the given signer and hash algorithm.
func ToSignatureAlgorithm(signer crypto.Signer, hash crypto.Hash) (x509.SignatureAlgorithm, error) {
	if signer == nil {
		return x509.UnknownSignatureAlgorithm, errors.New("signer is nil")
	}

	pub := signer.Public()
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return x509.SHA256WithRSA, nil
		case crypto.SHA384:
			return x509.SHA384WithRSA, nil
		case crypto.SHA512:
			return x509.SHA512WithRSA, nil
		case crypto.SHA1:
			return x509.SHA1WithRSA, nil
		case crypto.MD5:
			return x509.MD5WithRSA, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported hash algorithm for RSA: %v", hash)
		}
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return x509.ECDSAWithSHA256, nil
		case crypto.SHA384:
			return x509.ECDSAWithSHA384, nil
		case crypto.SHA512:
			return x509.ECDSAWithSHA512, nil
		case crypto.SHA1:
			return x509.ECDSAWithSHA1, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported hash algorithm for ECDSA: %v", hash)
		}
	case ed25519.PublicKey:
		// Ed25519 has a fixed signature so we don't need to check the hash
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported public key type: %T", pub)
	}
}
