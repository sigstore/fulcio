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
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"go.step.sm/crypto/pemutil"
)

func loadKeyPair(certPath, keyPath, keyPass string) (*ca.SignerCertsMutex, error) {
	var (
		certs []*x509.Certificate
		err   error
		key   crypto.Signer
	)

	data, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, err
	}
	certs, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if keyPass != "" {
		opaqueKey, err := pemutil.Read(keyPath, pemutil.WithPassword([]byte(keyPass)))
		if err != nil {
			return nil, err
		}

		var ok bool
		key, ok = opaqueKey.(crypto.Signer)
		if !ok {
			return nil, errors.New(`fileca: loaded private key can't be used to sign`)
		}
	} else {
		key, err = loadUnencryptedKey(keyPath)
		if err != nil {
			return nil, err
		}
	}

	if err := ca.VerifyCertChain(certs, key); err != nil {
		return nil, err
	}

	return &ca.SignerCertsMutex{Certs: certs, Signer: key}, nil
}

func loadUnencryptedKey(keyPath string) (crypto.Signer, error) {
	data, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("fileca: failed to decode PEM block from private key file")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return nil, errors.New("fileca: private key is encrypted, provide a password with --fileca-key-passwd")
	}

	var key crypto.Signer
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := parsed.(type) {
		case *ecdsa.PrivateKey:
			key = k
		case *rsa.PrivateKey:
			key = k
		case ed25519.PrivateKey:
			key = k
		default:
			return nil, errors.New("fileca: unsupported key type in PKCS#8 container")
		}
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("fileca: unsupported PEM block type: " + block.Type)
	}

	return key, nil
}
