// Copyright 2024 The Sigstore Authors.
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

package certmaker

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	// returned when certificate file is not found
	ErrCertificateNotFound = errors.New("certificate file not found")

	// returned when PEM decoding fails
	ErrInvalidPEM = errors.New("invalid PEM format")

	// returned when PEM block contains no certificate
	ErrNoCertificateData = errors.New("no certificate data in PEM block")

	// returned when certificate public key doesn't match KMS key
	ErrKeyMismatch = errors.New("certificate public key does not match KMS key")
)

// reads a PEM-encoded X.509 certificate from the
// specified file path and returns the parsed certificate.
func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	// read cert file
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrCertificateNotFound, path)
		}
		return nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	// decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: file %s contains no valid PEM data", ErrInvalidPEM, path)
	}

	// verify it's a CERTIFICATE block
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE block, got %s in file %s", ErrInvalidPEM, block.Type, path)
	}

	// check cert data
	if len(block.Bytes) == 0 {
		return nil, fmt.Errorf("%w: PEM block is empty in file %s", ErrNoCertificateData, path)
	}

	// parse X.509 cert
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate from %s: %w", path, err)
	}

	return cert, nil
}

// verifies that the public key in the given certificate
// matches the public key from the KMS SignerVerifier.
func ValidateCertificateKeyMatch(cert *x509.Certificate, sv signature.SignerVerifier) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}
	if sv == nil {
		return fmt.Errorf("signer verifier is nil")
	}

	// get public key from KMS
	kmsPubKey, err := sv.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// get public key from cert
	certPubKey := cert.PublicKey

	// compare public keys
	if !publicKeysEqual(certPubKey, kmsPubKey) {
		return fmt.Errorf("%w: certificate public key does not match KMS key", ErrKeyMismatch)
	}

	return nil
}

// compares two public keys for equality.
// supports RSA, ECDSA, and Ed25519 key types.
func publicKeysEqual(key1, key2 crypto.PublicKey) bool {
	switch k1 := key1.(type) {
	case *rsa.PublicKey:
		k2, ok := key2.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return k1.N.Cmp(k2.N) == 0 && k1.E == k2.E

	case *ecdsa.PublicKey:
		k2, ok := key2.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return k1.Curve == k2.Curve && k1.X.Cmp(k2.X) == 0 && k1.Y.Cmp(k2.Y) == 0

	case ed25519.PublicKey:
		k2, ok := key2.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return bytes.Equal(k1, k2)

	default:
		// for unknown key types, attempt byte comparison if possible; a fallback that may not work for all key types
		return false
	}
}
