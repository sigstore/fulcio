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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSignerVerifier implements signature.SignerVerifier for testing
type mockSignerVerifier struct {
	key             crypto.PrivateKey
	err             error
	publicKeyFunc   func() (crypto.PublicKey, error)
	signMessageFunc func(message io.Reader, opts ...signature.SignOption) ([]byte, error)
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
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return k.Sign(rand.Reader, digest, crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
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
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (m *mockSignerVerifier) Close() error {
	return nil
}

func (m *mockSignerVerifier) DefaultHashFunction() crypto.Hash {
	return crypto.SHA256
}

func (m *mockSignerVerifier) Bytes() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerVerifier) KeyID() (string, error) {
	return "mock-key-id", nil
}

func (m *mockSignerVerifier) Status() error {
	return nil
}

func (m *mockSignerVerifier) CryptoSigner(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.err != nil {
		return nil, nil, m.err
	}

	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return k, crypto.SHA256, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type")
	}
}

var (
	originalInitKMS = InitKMS
)

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  KMSConfig
		wantErr string
	}{
		{
			name:    "empty KMS type",
			config:  KMSConfig{},
			wantErr: "KMS type cannot be empty",
		},
		{
			name: "missing key IDs",
			config: KMSConfig{
				Type:    "awskms",
				Options: map[string]string{"aws-region": "us-west-2"},
			},
			wantErr: "RootKeyID must be specified",
		},
		{
			name: "missing leaf key ID",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"aws-region": "us-west-2"},
				RootKeyID: "alias/test-key",
			},
			wantErr: "LeafKeyID must be specified",
		},
		{
			name: "AWS KMS missing region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-key",
				LeafKeyID: "alias/test-leaf-key",
			},
			wantErr: "aws-region is required for AWS KMS",
		},
		{
			name: "Azure KMS missing tenant ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				Options:   map[string]string{},
			},
			wantErr: "tenant-id is required for Azure KMS",
		},
		{
			name: "Azure KMS missing vault parameter",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key",
				Options:   map[string]string{"azure-tenant-id": "test-tenant"},
			},
			wantErr: "azurekms RootKeyID must contain ';vault=' parameter",
		},
		{
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "test-key",
			},
			wantErr: "unsupported KMS type",
		},
		{
			name: "GCP KMS missing cryptoKeyVersions",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
			},
			wantErr: "gcpkms RootKeyID must contain '/cryptoKeyVersions/'",
		},
		{
			name: "GCP KMS invalid key format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-format",
			},
			wantErr: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "HashiVault KMS missing options",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/test-key",
			},
			wantErr: "options map is required for HashiVault KMS",
		},
		{
			name: "HashiVault KMS missing token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/test-key",
				Options:   map[string]string{"vault-address": "http://vault:8200"},
			},
			wantErr: "token is required for HashiVault KMS",
		},
		{
			name: "HashiVault KMS missing address",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/test-key",
				Options:   map[string]string{"vault-token": "test-token"},
			},
			wantErr: "address is required for HashiVault KMS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() string
		wantError string
	}{
		{
			name: "nonexistent_file",
			setup: func() string {
				return "/nonexistent/template.json"
			},
			wantError: "no such file or directory",
		},
		{
			name: "wrong_extension",
			setup: func() string {
				tmpFile, err := os.CreateTemp("", "template-*.txt")
				require.NoError(t, err)
				defer tmpFile.Close()
				return tmpFile.Name()
			},
			wantError: "template file must have .json extension",
		},
		{
			name: "valid_JSON_template",
			setup: func() string {
				tmpFile, err := os.CreateTemp("", "template-*.json")
				require.NoError(t, err)
				defer tmpFile.Close()

				content := []byte(`{
					"subject": {
						"commonName": "Test CA"
					},
					"issuer": {
						"commonName": "Test CA"
					},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
					},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`)
				_, err = tmpFile.Write(content)
				require.NoError(t, err)

				return tmpFile.Name()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			defer func() {
				if _, err := os.Stat(path); err == nil {
					os.Remove(path)
				}
			}()

			err := ValidateTemplatePath(path)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCertificates(t *testing.T) {
	defer func() { originalInitKMS = InitKMS }()

	tests := []struct {
		name                     string
		config                   KMSConfig
		rootTemplatePath         string
		leafTemplatePath         string
		rootCertPath             string
		leafCertPath             string
		intermediateKeyID        string
		intermediateTemplatePath string
		intermediateCertPath     string
		setupMockSigner          func() signature.SignerVerifier
		wantError                string
	}{
		{
			name: "leaf_key_initialization_error",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "invalid-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				originalKMS := InitKMS
				InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
					if strings.Contains(config.LeafKeyID, "invalid-key") {
						return nil, fmt.Errorf("error initializing leaf KMS")
					}
					return &mockSignerVerifier{key: key}, nil
				}
				t.Cleanup(func() {
					InitKMS = originalKMS
				})
				return &mockSignerVerifier{key: key}
			},
			wantError: "error initializing leaf KMS",
		},
		{
			name: "leaf_public_key_error",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				originalKMS := InitKMS
				InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
					if strings.Contains(config.LeafKeyID, "leaf-key") {
						return &mockSignerVerifier{
							key: key,
							err: fmt.Errorf("error getting leaf public key"),
						}, nil
					}
					return &mockSignerVerifier{key: key}, nil
				}
				t.Cleanup(func() {
					InitKMS = originalKMS
				})
				return &mockSignerVerifier{key: key}
			},
			wantError: "error getting leaf public key",
		},
		{
			name: "intermediate_key_initialization_error",
			config: KMSConfig{
				Type:              "awskms",
				Options:           map[string]string{"region": "us-west-2"},
				RootKeyID:         "alias/root-key",
				IntermediateKeyID: "invalid-key",
				LeafKeyID:         "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			intermediateTemplatePath: func(t *testing.T) string {
				intermediateTemplate := filepath.Join(t.TempDir(), "intermediate.json")
				err := os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return intermediateTemplate
			}(t),
			rootCertPath:         filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:         filepath.Join(t.TempDir(), "leaf.crt"),
			intermediateKeyID:    "invalid-key",
			intermediateCertPath: filepath.Join(t.TempDir(), "intermediate.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				originalKMS := InitKMS
				InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
					if strings.Contains(config.IntermediateKeyID, "invalid-key") {
						return nil, fmt.Errorf("error initializing intermediate KMS")
					}
					return &mockSignerVerifier{key: key}, nil
				}
				t.Cleanup(func() {
					InitKMS = originalKMS
				})
				return &mockSignerVerifier{key: key}
			},
			wantError: "error initializing intermediate KMS",
		},
		{
			name: "intermediate_public_key_error",
			config: KMSConfig{
				Type:              "awskms",
				Options:           map[string]string{"region": "us-west-2"},
				RootKeyID:         "alias/root-key",
				IntermediateKeyID: "alias/intermediate-key",
				LeafKeyID:         "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			intermediateTemplatePath: func(t *testing.T) string {
				intermediateTemplate := filepath.Join(t.TempDir(), "intermediate.json")
				err := os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return intermediateTemplate
			}(t),
			rootCertPath:         filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:         filepath.Join(t.TempDir(), "leaf.crt"),
			intermediateKeyID:    "alias/intermediate-key",
			intermediateCertPath: filepath.Join(t.TempDir(), "intermediate.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				originalKMS := InitKMS
				InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
					if strings.Contains(config.IntermediateKeyID, "intermediate-key") {
						return &mockSignerVerifier{
							key: key,
							err: fmt.Errorf("error getting intermediate public key"),
						}, nil
					}
					return &mockSignerVerifier{key: key}, nil
				}
				t.Cleanup(func() {
					InitKMS = originalKMS
				})
				return &mockSignerVerifier{key: key}
			},
			wantError: "error getting intermediate public key",
		},
		{
			name: "invalid_leaf_template",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: "/nonexistent/leaf.json",
			rootCertPath:     filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:     filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}
			},
			wantError: "error parsing leaf template: error reading template file",
		},
		{
			name: "successful_certificate_creation",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{
					key: key,
					err: fmt.Errorf("error getting leaf public key: getting public key: operation error KMS: GetPublicKey, get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found"),
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return key.Public(), nil
					},
				}
			},
			wantError: "error getting leaf public key: getting public key: operation error KMS: GetPublicKey, get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found",
		},
		{
			name: "invalid_template_path",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "awskms:///arn:aws:kms:us-west-2:123456789012:key/root-key",
				LeafKeyID: "awskms:///arn:aws:kms:us-west-2:123456789012:key/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: "/nonexistent/leaf.json",
			rootCertPath:     filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:     filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}
			},
			wantError: "error parsing leaf template: error reading template file",
		},
		{
			name: "invalid_root_template_path",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: "/nonexistent/root.json",
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				return &mockSignerVerifier{
					key: nil,
					err: fmt.Errorf("no such file or directory"),
				}
			},
			wantError: "error parsing root template: error reading template file",
		},
		{
			name: "root_cert_write_error",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: "/nonexistent/directory/root.crt",
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return key.Public(), nil
					},
				}
			},
			wantError: "failed to create file",
		},
		{
			name: "leaf_cert_write_error",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: "/nonexistent/directory/leaf.crt",
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return key.Public(), nil
					},
				}
			},
			wantError: "failed to create file",
		},
		{
			name: "signing_error",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				return &mockSignerVerifier{
					key: nil,
					err: fmt.Errorf("signing error"),
					publicKeyFunc: func() (crypto.PublicKey, error) {
						key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						return key.Public(), nil
					},
				}
			},
			wantError: "signing error",
		},
		{
			name: "intermediate_cert_write_error",
			config: KMSConfig{
				Type:              "awskms",
				Options:           map[string]string{"region": "us-west-2"},
				RootKeyID:         "alias/root-key",
				IntermediateKeyID: "alias/intermediate-key",
				LeafKeyID:         "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			intermediateTemplatePath: func(t *testing.T) string {
				intermediateTemplate := filepath.Join(t.TempDir(), "intermediate.json")
				err := os.WriteFile(intermediateTemplate, []byte(`{
					"subject": {"commonName": "Test Intermediate CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 0},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return intermediateTemplate
			}(t),
			rootCertPath:         filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:         filepath.Join(t.TempDir(), "leaf.crt"),
			intermediateKeyID:    "alias/intermediate-key",
			intermediateCertPath: filepath.Join(t.TempDir(), "intermediate.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				return &mockSignerVerifier{
					key: nil,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return nil, fmt.Errorf("error writing intermediate certificate")
					},
				}
			},
			wantError: "error writing intermediate certificate",
		},
		{
			name: "invalid_cert_path",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: func(t *testing.T) string {
				leafTemplate := filepath.Join(t.TempDir(), "leaf.json")
				err := os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"],
					"basicConstraints": {"isCA": false},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return leafTemplate
			}(t),
			rootCertPath: "/nonexistent/directory/root.crt",
			leafCertPath: filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &mockSignerVerifier{key: key}
			},
			wantError: "failed to create file",
		},
		{
			name: "invalid_leaf_template_path#01",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"region": "us-west-2"},
				RootKeyID: "alias/root-key",
				LeafKeyID: "alias/leaf-key",
			},
			rootTemplatePath: func(t *testing.T) string {
				rootTemplate := filepath.Join(t.TempDir(), "root.json")
				err := os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				require.NoError(t, err)
				return rootTemplate
			}(t),
			leafTemplatePath: "/nonexistent/leaf.json",
			rootCertPath:     filepath.Join(t.TempDir(), "root.crt"),
			leafCertPath:     filepath.Join(t.TempDir(), "leaf.crt"),
			setupMockSigner: func() signature.SignerVerifier {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				originalKMS := InitKMS
				InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
					if strings.Contains(config.LeafKeyID, "leaf-key") {
						return &mockSignerVerifier{
							key: key,
							publicKeyFunc: func() (crypto.PublicKey, error) {
								return key.Public(), nil
							},
							signMessageFunc: func(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
								digest := make([]byte, 32)
								if _, err := message.Read(digest); err != nil {
									return nil, err
								}
								return key.Sign(rand.Reader, digest, crypto.SHA256)
							},
						}, nil
					}
					return &mockSignerVerifier{
						key: key,
						publicKeyFunc: func() (crypto.PublicKey, error) {
							return key.Public(), nil
						},
						signMessageFunc: func(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
							digest := make([]byte, 32)
							if _, err := message.Read(digest); err != nil {
								return nil, err
							}
							return key.Sign(rand.Reader, digest, crypto.SHA256)
						},
					}, nil
				}
				t.Cleanup(func() {
					InitKMS = originalKMS
				})
				return &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return key.Public(), nil
					},
					signMessageFunc: func(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
						digest := make([]byte, 32)
						if _, err := message.Read(digest); err != nil {
							return nil, err
						}
						return key.Sign(rand.Reader, digest, crypto.SHA256)
					},
				}
			},
			wantError: "error parsing leaf template: error reading template file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateCertificates(tt.setupMockSigner(), tt.config,
				tt.rootTemplatePath, tt.leafTemplatePath,
				tt.rootCertPath, tt.leafCertPath,
				tt.intermediateKeyID, tt.intermediateTemplatePath, tt.intermediateCertPath)

			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				_, err = os.Stat(tt.rootCertPath)
				require.NoError(t, err)
				_, err = os.Stat(tt.leafCertPath)
				require.NoError(t, err)
				if tt.intermediateKeyID != "" {
					_, err = os.Stat(tt.intermediateCertPath)
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestInitKMS(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError bool
	}{
		{
			name: "empty_KMS_type",
			config: KMSConfig{
				RootKeyID: "test-key",
			},
			wantError: true,
		},
		{
			name: "missing_key_IDs",
			config: KMSConfig{
				Type:    "awskms",
				Options: map[string]string{"region": "us-west-2"},
			},
			wantError: true,
		},
		{
			name: "AWS_KMS_missing_region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			},
			wantError: true,
		},
		{
			name: "Azure_KMS_missing_tenant_ID",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				Options:   map[string]string{},
			},
			wantError: true,
		},
		{
			name: "Azure_KMS_missing_vault_parameter",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key",
				Options: map[string]string{
					"azure-tenant-id": "test-tenant",
				},
			},
			wantError: true,
		},
		{
			name: "unsupported_KMS_type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "test-key",
			},
			wantError: true,
		},
		{
			name: "aws_kms_valid_config",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: true,
		},
		{
			name: "azure_kms_valid_config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=test-leaf-key;vault=test-vault",
				Options: map[string]string{
					"azure-tenant-id": "test-tenant",
				},
			},
			wantError: false,
		},
		{
			name: "gcp_kms_valid_config",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-leaf-key/cryptoKeyVersions/1",
			},
			wantError: false,
		},
		{
			name: "hashivault_kms_valid_config",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/my-key",
				Options: map[string]string{
					"vault-token":   "test-token",
					"vault-address": "http://vault:8200",
				},
			},
			wantError: true,
		},
		{
			name: "aws_kms_nil_signer",
			config: KMSConfig{
				Type:      "awskms",
				Options:   map[string]string{"aws-region": "us-west-2"},
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
			},
			wantError: true,
		},
		{
			name: "aws_kms_with_endpoint",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-key",
				LeafKeyID: "alias/test-leaf-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: false,
		},
		{
			name: "aws_kms_with_alias",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-key",
				LeafKeyID: "alias/test-leaf-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: false,
		},
		{
			name: "aws_kms_with_arn",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
				Options:   map[string]string{"aws-region": "us-west-2"},
			},
			wantError: true,
		},
		{
			name: "gcp_kms_with_cryptoKeyVersions",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-leaf-key/cryptoKeyVersions/1",
			},
			wantError: false,
		},
		{
			name: "hashivault_kms_with_transit_keys",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/test-key",
				Options: map[string]string{
					"vault-token":   "test-token",
					"vault-address": "http://vault:8200",
				},
			},
			wantError: true,
		},
		{
			name: "gcp_kms_with_uri",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "gcpkms://projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
			},
			wantError: true,
		},
		{
			name: "hashivault_kms_with_uri",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "hashivault://transit/keys/test-key",
				Options: map[string]string{
					"vault-token":   "test-token",
					"vault-address": "http://vault:8200",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InitKMS(context.Background(), tt.config)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTemplateWithExtKeyUsage(t *testing.T) {
	template := &CertificateTemplate{
		Subject: struct {
			Country            []string `json:"country,omitempty"`
			Organization       []string `json:"organization,omitempty"`
			OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
			CommonName         string   `json:"commonName"`
		}{
			CommonName: "Test CA",
		},
		Issuer: struct {
			CommonName string `json:"commonName"`
		}{
			CommonName: "Test CA",
		},
		KeyUsage:    []string{"certSign", "crlSign"},
		ExtKeyUsage: []string{"serverAuth", "clientAuth"},
		BasicConstraints: struct {
			IsCA       bool `json:"isCA"`
			MaxPathLen int  `json:"maxPathLen"`
		}{
			IsCA:       true,
			MaxPathLen: 1,
		},
		NotBefore: "2024-01-01T00:00:00Z",
		NotAfter:  "2025-01-01T00:00:00Z",
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	err := ValidateTemplate(template, parent, "root")
	require.NoError(t, err)
}

func TestValidateTemplateWithInvalidExtKeyUsage(t *testing.T) {
	template := &CertificateTemplate{
		Subject: struct {
			Country            []string `json:"country,omitempty"`
			Organization       []string `json:"organization,omitempty"`
			OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
			CommonName         string   `json:"commonName"`
		}{
			CommonName: "Test Leaf",
		},
		Issuer: struct {
			CommonName string `json:"commonName"`
		}{
			CommonName: "Test CA",
		},
		KeyUsage:    []string{"digitalSignature"},
		ExtKeyUsage: []string{"nonExistentUsage", "anotherInvalidUsage"},
		BasicConstraints: struct {
			IsCA       bool `json:"isCA"`
			MaxPathLen int  `json:"maxPathLen"`
		}{
			IsCA: false,
		},
		NotBefore: "2024-01-01T00:00:00Z",
		NotAfter:  "2025-01-01T00:00:00Z",
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Parent CA",
		},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	err := ValidateTemplate(template, parent, "leaf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must have codeSign extended key usage")

	template.ExtKeyUsage = append(template.ExtKeyUsage, "CodeSigning")
	err = ValidateTemplate(template, parent, "leaf")
	require.NoError(t, err)
}

func TestWriteCertificateToFile(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		path      string
		wantError string
		wantType  string
	}{
		{
			name: "write_to_nonexistent_directory",
			cert: &x509.Certificate{
				Raw: []byte("test"),
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				IsCA: true,
			},
			path:      "/nonexistent/directory/cert.crt",
			wantError: "failed to create file",
		},
		{
			name: "write_to_readonly_directory",
			cert: &x509.Certificate{
				Raw: []byte("test"),
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				IsCA: true,
			},
			path:      filepath.Join(os.TempDir(), "readonly", "cert.crt"),
			wantError: "failed to create file",
		},
		{
			name: "write_root_certificate",
			cert: &x509.Certificate{
				Raw: []byte("test"),
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				IsCA:       true,
				MaxPathLen: 1,
			},
			path:     filepath.Join(os.TempDir(), "root.crt"),
			wantType: "root",
		},
		{
			name: "write_intermediate_certificate",
			cert: &x509.Certificate{
				Raw: []byte("test"),
				Subject: pkix.Name{
					CommonName: "Test Intermediate CA",
				},
				IsCA:       true,
				MaxPathLen: 0,
			},
			path:     filepath.Join(os.TempDir(), "intermediate.crt"),
			wantType: "intermediate",
		},
		{
			name: "write_leaf_certificate",
			cert: &x509.Certificate{
				Raw: []byte("test"),
				Subject: pkix.Name{
					CommonName: "Test Leaf",
				},
				IsCA: false,
			},
			path:     filepath.Join(os.TempDir(), "leaf.crt"),
			wantType: "leaf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.name, "readonly") {
				dir := filepath.Dir(tt.path)
				err := os.MkdirAll(dir, 0444)
				require.NoError(t, err)
				defer os.RemoveAll(dir)
			}

			err := WriteCertificateToFile(tt.cert, tt.path)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				_, err = os.Stat(tt.path)
				require.NoError(t, err)
				if tt.wantType != "" {
					assert.Contains(t, tt.path, tt.wantType)
				}
				os.Remove(tt.path)
			}
		})
	}
}

func TestWriteCertificateToFileErrors(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	parsedCert, err := x509.ParseCertificate(cert)
	require.NoError(t, err)

	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantError string
	}{
		{
			name: "directory_exists_as_file",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "cert.crt")
				err := os.MkdirAll(path, 0755)
				require.NoError(t, err)
				return path
			},
			wantError: "failed to create file",
		},
		{
			name: "permission_denied",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				err := os.Chmod(tmpDir, 0000)
				require.NoError(t, err)
				return filepath.Join(tmpDir, "cert.crt")
			},
			wantError: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			err := WriteCertificateToFile(parsedCert, path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesTemplateValidation(t *testing.T) {
	tmpDir := t.TempDir()

	rootTemplate := filepath.Join(tmpDir, "root.json")
	err := os.WriteFile(rootTemplate, []byte(`{
		"subject": {"commonName": "Test Root CA"},
		"issuer": {"commonName": "Test Root CA"},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {"isCA": true, "maxPathLen": 1},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	leafTemplate := filepath.Join(tmpDir, "leaf.json")
	err = os.WriteFile(leafTemplate, []byte(`{
		"subject": {"commonName": "Test Leaf"},
		"keyUsage": ["digitalSignature"],
		"basicConstraints": {"isCA": false},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`), 0600)
	require.NoError(t, err)

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "alias/root-key",
		LeafKeyID: "alias/leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sv := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return key.Public(), nil
		},
	}

	err = CreateCertificates(sv, config,
		rootTemplate,
		leafTemplate,
		filepath.Join(tmpDir, "root.crt"),
		filepath.Join(tmpDir, "leaf.crt"),
		"",
		"",
		"")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing leaf template: Fulcio leaf certificates must have codeSign extended key usage")
}
