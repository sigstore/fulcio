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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	// returned when certificate file is not found
	ErrCertificateNotFound = errors.New("certificate file not found")

	// returned when PEM decoding fails or wrong block type
	ErrInvalidPEM = errors.New("invalid PEM format")

	// returned when PEM block contains no certificate
	ErrNoCertificateData = errors.New("no certificate data in PEM block")

	// returned when certificate public key doesn't match KMS key
	ErrKeyMismatch = errors.New("certificate public key does not match KMS key")
)

// reads a PEM-encoded X.509 certificate from the
// specified file path and returns the parsed certificate.
func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrCertificateNotFound, path)
		}
		return nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	// Minimal validation to preserve existing error semantics
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: file %s contains no valid PEM data", ErrInvalidPEM, path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE block, got %s in file %s", ErrInvalidPEM, block.Type, path)
	}
	if len(block.Bytes) == 0 {
		return nil, fmt.Errorf("%w: PEM block is empty in file %s", ErrNoCertificateData, path)
	}

	// Use cryptoutils to parse one or more certs, return the first
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate from %s: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoCertificateData, path)
	}
	return certs[0], nil
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

	// compare public keys using sigstore cryptoutils
	if err := cryptoutils.EqualKeys(certPubKey, kmsPubKey); err != nil {
		return fmt.Errorf("%w: %v", ErrKeyMismatch, err)
	}

	return nil
}
