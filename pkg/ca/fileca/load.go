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

package fileca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"go.step.sm/crypto/pemutil"
)

func loadKeyPair(certPath, keyPath, keyPass string) ([]*x509.Certificate, crypto.Signer, error) {

	var (
		certs []*x509.Certificate
		err   error
		key   crypto.Signer
	)

	// NB: certs are ordered from leaf at certs[0] to root at
	// certs[len(certs)-1]
	certs, err = pemutil.ReadCertificateBundle(certPath)
	if err != nil {
		return nil, nil, err
	}

	// Verify certificate chain
	{
		roots := x509.NewCertPool()
		roots.AddCert(certs[len(certs)-1])

		intermediates := x509.NewCertPool()
		if len(certs) > 2 {
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
			return nil, nil, err
		}

		if !certs[0].IsCA {
			return nil, nil, errors.New(`fileca: certificate is not a CA`)
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
				return nil, nil, errors.New(`fileca: certificate must have extended key usage code signing set to sign code signing certificates`)
			}
		}
	}

	{
		opaqueKey, err := pemutil.Read(keyPath, pemutil.WithPassword([]byte(keyPass)))
		if err != nil {
			return nil, nil, err
		}

		var ok bool
		key, ok = opaqueKey.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New(`fileca: loaded private key can't be used to sign`)
		}
	}

	if !valid(certs[0], key) {
		return nil, nil, errors.New(`fileca: certificate public key and private key don't match`)
	}

	return certs, key, nil
}

func valid(cert *x509.Certificate, key crypto.Signer) bool {
	if cert == nil || key == nil {
		return false
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return false
		}
		if pub.N.Cmp(priv.N) != 0 {
			return false
		}
	case *ecdsa.PublicKey:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return false
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return false
		}
	case ed25519.PublicKey:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return false
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return false
		}
	default:
		return false
	}

	return true
}
