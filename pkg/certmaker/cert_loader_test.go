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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper func to create a test certificate
func createTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// helper func to write certificate to PEM file
func writeCertToPEM(t *testing.T, cert *x509.Certificate, path string) {
	t.Helper()

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(path, pemData, 0600))
}

func TestLoadCertificateFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	// create a valid test certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	validCert := createTestCertificate(t, key)

	tests := []struct {
		name      string
		setup     func(string) string // returns path to test file
		wantError error
		checkCert func(*testing.T, *x509.Certificate)
	}{
		{
			name: "valid PEM certificate",
			setup: func(dir string) string {
				path := filepath.Join(dir, "valid.pem")
				writeCertToPEM(t, validCert, path)
				return path
			},
			wantError: nil,
			checkCert: func(t *testing.T, cert *x509.Certificate) {
				assert.NotNil(t, cert)
				assert.Equal(t, validCert.Subject.CommonName, cert.Subject.CommonName)
			},
		},
		{
			name: "file not found",
			setup: func(dir string) string {
				return filepath.Join(dir, "nonexistent.pem")
			},
			wantError: ErrCertificateNotFound,
		},
		{
			name: "invalid PEM format",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid.pem")
				require.NoError(t, os.WriteFile(path, []byte("not a PEM file"), 0600))
				return path
			},
			wantError: ErrInvalidPEM,
		},
		{
			name: "wrong PEM block type",
			setup: func(dir string) string {
				path := filepath.Join(dir, "wrong-type.pem")
				block := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: []byte("some data"),
				}
				pemData := pem.EncodeToMemory(block)
				require.NoError(t, os.WriteFile(path, pemData, 0600))
				return path
			},
			wantError: ErrInvalidPEM,
		},
		{
			name: "empty PEM block",
			setup: func(dir string) string {
				path := filepath.Join(dir, "empty.pem")
				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte{},
				}
				pemData := pem.EncodeToMemory(block)
				require.NoError(t, os.WriteFile(path, pemData, 0600))
				return path
			},
			wantError: ErrNoCertificateData,
		},
		{
			name: "malformed certificate data",
			setup: func(dir string) string {
				path := filepath.Join(dir, "malformed.pem")
				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("not a valid certificate"),
				}
				pemData := pem.EncodeToMemory(block)
				require.NoError(t, os.WriteFile(path, pemData, 0600))
				return path
			},
			wantError: nil, // will fail during x509.ParseCertificate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(tmpDir)
			cert, err := LoadCertificateFromFile(path)

			if tt.wantError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantError)
			} else if tt.checkCert != nil {
				require.NoError(t, err)
				tt.checkCert(t, cert)
			} else {
				// for malformed certificate test
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to parse X.509 certificate")
			}
		})
	}
}

func TestValidateCertificateKeyMatch(t *testing.T) {
	tests := []struct {
		name      string
		setupCert func(*testing.T) *x509.Certificate
		setupSV   func(*testing.T, crypto.PublicKey) *mockSignerVerifier
		wantError error
	}{
		{
			name: "matching ECDSA keys",
			setupCert: func(t *testing.T) *x509.Certificate {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				// create a new key with the same public key
				ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
				require.True(t, ok)
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return ecdsaPub, nil
					},
				}
			},
			wantError: nil,
		},
		{
			name: "matching RSA keys",
			setupCert: func(t *testing.T) *x509.Certificate {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				rsaPub, ok := pubKey.(*rsa.PublicKey)
				require.True(t, ok)
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return rsaPub, nil
					},
				}
			},
			wantError: nil,
		},
		{
			name: "matching Ed25519 keys",
			setupCert: func(t *testing.T) *x509.Certificate {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				ed25519Pub, ok := pubKey.(ed25519.PublicKey)
				require.True(t, ok)
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return ed25519Pub, nil
					},
				}
			},
			wantError: nil,
		},
		{
			name: "mismatched ECDSA keys",
			setupCert: func(t *testing.T) *x509.Certificate {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				// generate a different key
				differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return differentKey.Public(), nil
					},
				}
			},
			wantError: ErrKeyMismatch,
		},
		{
			name: "mismatched key types (RSA vs ECDSA)",
			setupCert: func(t *testing.T) *x509.Certificate {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				// return ECDSA key instead of RSA
				ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return ecdsaKey.Public(), nil
					},
				}
			},
			wantError: ErrKeyMismatch,
		},
		{
			name: "nil certificate",
			setupCert: func(t *testing.T) *x509.Certificate {
				return nil
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				return &mockSignerVerifier{}
			},
			wantError: nil, // will get "certificate is nil" error
		},
		{
			name: "KMS error getting public key",
			setupCert: func(t *testing.T) *x509.Certificate {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return createTestCertificate(t, key)
			},
			setupSV: func(t *testing.T, pubKey crypto.PublicKey) *mockSignerVerifier {
				return &mockSignerVerifier{
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return nil, errors.New("KMS error")
					},
				}
			},
			wantError: nil, // will get wrapped KMS error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.setupCert(t)
			var sv *mockSignerVerifier
			if cert != nil {
				sv = tt.setupSV(t, cert.PublicKey)
			} else {
				sv = tt.setupSV(t, nil)
			}

			err := ValidateCertificateKeyMatch(cert, sv)

			if tt.wantError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantError)
			} else if tt.name == "nil certificate" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "certificate is nil")
			} else if tt.name == "KMS error getting public key" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to get public key from KMS")
			} else {
				require.NoError(t, err)
			}
		})
	}

	// test nil signer verifier separately to avoid Go typed nil issues
	t.Run("nil signer verifier", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		cert := createTestCertificate(t, key)

		err = ValidateCertificateKeyMatch(cert, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer verifier is nil")
	})
}

func TestPublicKeysEqual(t *testing.T) {
	// generate test keys
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ed25519Pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519Pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name  string
		key1  crypto.PublicKey
		key2  crypto.PublicKey
		equal bool
	}{
		{
			name:  "same RSA key",
			key1:  rsaKey1.Public(),
			key2:  rsaKey1.Public(),
			equal: true,
		},
		{
			name:  "different RSA keys",
			key1:  rsaKey1.Public(),
			key2:  rsaKey2.Public(),
			equal: false,
		},
		{
			name:  "same ECDSA key",
			key1:  ecdsaKey1.Public(),
			key2:  ecdsaKey1.Public(),
			equal: true,
		},
		{
			name:  "different ECDSA keys",
			key1:  ecdsaKey1.Public(),
			key2:  ecdsaKey2.Public(),
			equal: false,
		},
		{
			name:  "same Ed25519 key",
			key1:  ed25519Pub1,
			key2:  ed25519Pub1,
			equal: true,
		},
		{
			name:  "different Ed25519 keys",
			key1:  ed25519Pub1,
			key2:  ed25519Pub2,
			equal: false,
		},
		{
			name:  "RSA vs ECDSA",
			key1:  rsaKey1.Public(),
			key2:  ecdsaKey1.Public(),
			equal: false,
		},
		{
			name:  "ECDSA vs Ed25519",
			key1:  ecdsaKey1.Public(),
			key2:  ed25519Pub1,
			equal: false,
		},
		{
			name:  "RSA vs Ed25519",
			key1:  rsaKey1.Public(),
			key2:  ed25519Pub1,
			equal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := publicKeysEqual(tt.key1, tt.key2)
			assert.Equal(t, tt.equal, result)
		})
	}
}
