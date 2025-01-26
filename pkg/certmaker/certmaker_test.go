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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSignerVerifier implements signature.SignerVerifier and CryptoSignerVerifier for testing
type mockSignerVerifier struct {
	key              crypto.Signer
	err              error
	publicKeyFunc    func() (crypto.PublicKey, error)
	signMessageFunc  func(message io.Reader, opts ...signature.SignOption) ([]byte, error)
	cryptoSignerFunc func(ctx context.Context, errHandler func(error)) (crypto.Signer, crypto.SignerOpts, error)
}

func (m *mockSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	if m.signMessageFunc != nil {
		return m.signMessageFunc(message, opts...)
	}
	if m.err != nil {
		return nil, m.err
	}
	digest := make([]byte, 32)
	if _, err := message.Read(digest); err != nil {
		return nil, err
	}
	return m.key.Sign(rand.Reader, digest, crypto.SHA256)
}

func (m *mockSignerVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}

func (m *mockSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.publicKeyFunc != nil {
		return m.publicKeyFunc()
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.key.Public(), nil
}

func (m *mockSignerVerifier) Close() error { return nil }

func (m *mockSignerVerifier) DefaultHashFunction() crypto.Hash { return crypto.SHA256 }

func (m *mockSignerVerifier) Bytes() ([]byte, error) { return nil, nil }

func (m *mockSignerVerifier) KeyID() (string, error) { return "", nil }

func (m *mockSignerVerifier) Status() error { return nil }

func (m *mockSignerVerifier) CryptoSigner(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.cryptoSignerFunc != nil {
		return m.cryptoSignerFunc(context.Background(), nil)
	}
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.key, crypto.SHA256, nil
}

func TestCreateCertificates(t *testing.T) {
	originalInitKMS := InitKMS
	defer func() { InitKMS = originalInitKMS }()

	tmpDir := t.TempDir()

	rootTemplate := `{
					"subject": {
			"commonName": "Test Root CA"
					},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
		}
	}`

	intermediateTemplate := `{
		"subject": {
			"commonName": "Test Intermediate CA"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	rootTmplPath := filepath.Join(tmpDir, "root.json")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf.json")
	rootCertPath := filepath.Join(tmpDir, "root.pem")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")
	leafCertPath := filepath.Join(tmpDir, "leaf.pem")

	require.NoError(t, os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600))
	require.NoError(t, os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0600))
	require.NoError(t, os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600))

	mockSigner := &mockSignerVerifier{
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return nil, fmt.Errorf("test error")
		},
	}

	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return mockSigner, nil
	}

	err := CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "",
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting root public key: test error")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner = &mockSignerVerifier{
		key: key,
		cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
			return nil, nil, fmt.Errorf("crypto signer error")
		},
	}

	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return mockSigner, nil
	}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "",
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting root crypto signer: crypto signer error")

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner = &mockSignerVerifier{
		key: key,
	}

	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return mockSigner, nil
	}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "",
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.NoError(t, err)

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.RootKeyID == "intermediate-key" {
			return nil, fmt.Errorf("intermediate KMS error")
		}
		return mockSigner, nil
	}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "intermediate-key", intermediateTmplPath, intermediateCertPath,
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error initializing intermediate KMS: intermediate KMS error")

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockIntermediateSigner := &mockSignerVerifier{
		key: intermediateKey,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return nil, fmt.Errorf("intermediate public key error")
		},
	}

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.RootKeyID == "intermediate-key" {
			return mockIntermediateSigner, nil
		}
		return mockSigner, nil
	}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "intermediate-key", intermediateTmplPath, intermediateCertPath,
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting intermediate public key: intermediate public key error")

	mockIntermediateSigner = &mockSignerVerifier{
		key: intermediateKey,
	}

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.RootKeyID == "intermediate-key" {
			return mockIntermediateSigner, nil
		}
		return mockSigner, nil
	}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "intermediate-key", intermediateTmplPath, intermediateCertPath,
		87600*time.Hour, 43800*time.Hour, 8760*time.Hour)

	require.NoError(t, err)

	_, err = os.Stat(rootCertPath)
	require.NoError(t, err)
	_, err = os.Stat(intermediateCertPath)
	require.NoError(t, err)
	_, err = os.Stat(leafCertPath)
	require.NoError(t, err)
}

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "valid AWS config",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
		},
		{
			name: "valid GCP config",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				Options:   map[string]string{"gcp-credentials-file": "/path/to/creds.json"},
			},
		},
		{
			name: "valid Azure config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1;vault=vault1",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
		},
		{
			name: "valid HashiVault config",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-token":   "token",
					"vault-address": "http://localhost:8200",
				},
			},
		},
		{
			name: "missing AWS region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
			wantError: "aws-region is required for AWS KMS",
		},
		{
			name: "missing Azure tenant ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=key1;vault=vault1",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
			},
			wantError: "options map is required for Azure KMS",
		},
		{
			name: "missing HashiVault token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-address": "http://localhost:8200",
				},
			},
			wantError: "vault-token is required for HashiVault KMS",
		},
		{
			name: "missing HashiVault address",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/root-key",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-token": "token",
				},
			},
			wantError: "vault-address is required for HashiVault KMS",
		},
		{
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "key1",
				LeafKeyID: "key2",
			},
			wantError: "unsupported KMS type: unsupported",
		},
		{
			name: "invalid AWS key ID format",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "invalid-key-id",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "AWS key ID region mismatch",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "region in ARN (us-east-1) does not match configured region (us-west-2)",
		},
		{
			name: "invalid GCP key ID format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid/key/path",
				LeafKeyID: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1",
				Options:   map[string]string{"gcp-credentials-file": "/path/to/creds.json"},
			},
			wantError: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "invalid Azure key ID format",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-key-id",
				LeafKeyID: "azurekms:name=key2;vault=vault1",
				Options:   map[string]string{"azure-tenant-id": "tenant-id"},
			},
			wantError: "azurekms RootKeyID must start with 'azurekms:name='",
		},
		{
			name: "invalid HashiVault key ID format",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "invalid/path",
				LeafKeyID: "transit/keys/leaf-key",
				Options: map[string]string{
					"vault-token":   "token",
					"vault-address": "http://localhost:8200",
				},
			},
			wantError: "hashivault RootKeyID must be in format: transit/keys/keyname",
		},
		{
			name: "missing root key ID",
			config: KMSConfig{
				Type:      "awskms",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "RootKeyID must be specified",
		},
		{
			name: "missing leaf key ID",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: "LeafKeyID must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWriteCertificateToFile(t *testing.T) {
	tests := []struct {
		name    string
		cert    *x509.Certificate
		path    string
		wantErr string
	}{
		{
			name: "valid_certificate",
			cert: &x509.Certificate{Raw: []byte("test")},
			path: filepath.Join(t.TempDir(), "valid.pem"),
		},
		{
			name:    "nil_certificate",
			cert:    nil,
			path:    filepath.Join(t.TempDir(), "nil.pem"),
			wantErr: "certificate is nil",
		},
		{
			name:    "certificate_with_no_raw_data",
			cert:    &x509.Certificate{},
			path:    filepath.Join(t.TempDir(), "no-raw.pem"),
			wantErr: "certificate has no raw data",
		},
		{
			name:    "invalid_file_path",
			cert:    &x509.Certificate{Raw: []byte("test")},
			path:    "/nonexistent/dir/cert.pem",
			wantErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteCertificateToFile(tt.cert, tt.path)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				data, err := os.ReadFile(tt.path)
				require.NoError(t, err)
				block, _ := pem.Decode(data)
				require.NotNil(t, block)
				require.Equal(t, "CERTIFICATE", block.Type)
			}
		})
	}
}
func TestToSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  crypto.PublicKey
		sigAlg  x509.SignatureAlgorithm
		wantAlg x509.SignatureAlgorithm
		wantErr string
	}{
		{
			name:    "nil_public_key",
			pubKey:  nil,
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.UnknownSignatureAlgorithm,
			wantErr: "public key is nil",
		},
		{
			name:    "unsupported_public_key_type",
			pubKey:  struct{}{},
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.UnknownSignatureAlgorithm,
			wantErr: "unsupported public key type",
		},
		{
			name:    "default_RSA",
			pubKey:  &rsa.PublicKey{},
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.SHA256WithRSA,
		},
		{
			name:    "SHA256WithRSA",
			pubKey:  &rsa.PublicKey{},
			sigAlg:  x509.SHA256WithRSA,
			wantAlg: x509.SHA256WithRSA,
		},
		{
			name:    "unsupported_RSA_algorithm",
			pubKey:  &rsa.PublicKey{},
			sigAlg:  x509.DSAWithSHA256,
			wantAlg: x509.UnknownSignatureAlgorithm,
			wantErr: "unsupported RSA signature algorithm: DSA-SHA256",
		},
		{
			name:    "default_ECDSA_P256",
			pubKey:  &ecdsa.PublicKey{Curve: elliptic.P256()},
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.ECDSAWithSHA256,
		},
		{
			name:    "unsupported_ECDSA_curve",
			pubKey:  &ecdsa.PublicKey{Curve: elliptic.P224()},
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.UnknownSignatureAlgorithm,
			wantErr: "unsupported elliptic curve for ECDSA",
		},
		{
			name:    "default_Ed25519",
			pubKey:  ed25519.PublicKey{},
			sigAlg:  x509.UnknownSignatureAlgorithm,
			wantAlg: x509.PureEd25519,
		},
		{
			name:    "unsupported_Ed25519_algorithm",
			pubKey:  ed25519.PublicKey{},
			sigAlg:  x509.SHA256WithRSA,
			wantAlg: x509.UnknownSignatureAlgorithm,
			wantErr: "unsupported Ed25519 signature algorithm: SHA256-RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := ToSignatureAlgorithm(tt.pubKey, tt.sigAlg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAlg, alg)
			}
		})
	}
}
