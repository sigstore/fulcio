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
	"errors"
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
	key              crypto.PrivateKey
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
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return k.Sign(rand.Reader, digest, crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (m *mockSignerVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return m.err
}

func (m *mockSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.publicKeyFunc != nil {
		return m.publicKeyFunc()
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.key == nil {
		return nil, fmt.Errorf("no key available")
	}
	switch k := m.key.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (m *mockSignerVerifier) Close() error { return nil }

func (m *mockSignerVerifier) DefaultHashFunction() crypto.Hash { return crypto.SHA256 }

func (m *mockSignerVerifier) Bytes() ([]byte, error) { return nil, nil }

func (m *mockSignerVerifier) KeyID() (string, error) { return "", nil }

func (m *mockSignerVerifier) Status() error { return nil }

func (m *mockSignerVerifier) CryptoSigner(ctx context.Context, errHandler func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	if m.cryptoSignerFunc != nil {
		return m.cryptoSignerFunc(ctx, errHandler)
	}
	if m.err != nil {
		return nil, nil, m.err
	}
	if m.key == nil {
		return nil, nil, fmt.Errorf("no key available")
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
	defer func() { InitKMS = originalInitKMS }()
	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{key: key}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"certLife": "",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "4380h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"]
	}`
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "root-key",
		LeafKeyID: "leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing root template: certLife must be specified")
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

type Subject struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	CommonName         string   `json:"commonName"`
}

type Issuer struct {
	CommonName string `json:"commonName"`
}

type BasicConstraints struct {
	IsCA       bool `json:"isCA"`
	MaxPathLen int  `json:"maxPathLen"`
}

func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "valid_template_with_duration-based_validity",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Root CA",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: BasicConstraints{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
			parent:    nil,
			certType:  "root",
			wantError: "",
		},
		{
			name: "invalid_extended_key_usage",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"invalid"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "Fulcio leaf certificates must have codeSign extended key usage",
		},
		{
			name: "invalid_duration_format",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "invalid",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "invalid certLife format: time: invalid duration \"invalid\"",
		},
		{
			name: "negative_duration",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "-8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "certLife must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.template, tt.parent, tt.certType)
			if tt.wantError == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestValidateTemplateWithValidFields(t *testing.T) {
	template := &CertificateTemplate{
		Subject: Subject{
			CommonName: "Test Root CA",
		},
		Issuer: Issuer{
			CommonName: "Test Root CA",
		},
		CertLifetime: "8760h",
		KeyUsage:     []string{"certSign", "crlSign"},
		BasicConstraints: BasicConstraints{
			IsCA:       true,
			MaxPathLen: 1,
		},
	}

	err := ValidateTemplate(template, nil, "root")
	require.NoError(t, err)
}

func TestValidateTemplateWithDurationBasedValidity(t *testing.T) {
	template := &CertificateTemplate{
		Subject: Subject{
			CommonName: "Test Root CA",
		},
		Issuer: Issuer{
			CommonName: "Test Root CA",
		},
		CertLifetime: "8760h",
		KeyUsage:     []string{"certSign", "crlSign"},
		BasicConstraints: BasicConstraints{
			IsCA:       true,
			MaxPathLen: 1,
		},
	}

	err := ValidateTemplate(template, nil, "root")
	require.NoError(t, err)
}

func TestValidateTemplateWithInvalidExtKeyUsage(t *testing.T) {
	template := &CertificateTemplate{
		Subject: Subject{
			CommonName: "Test Leaf",
		},
		Issuer: Issuer{
			CommonName: "Test Root CA",
		},
		CertLifetime: "8760h",
		KeyUsage:     []string{"digitalSignature"},
		ExtKeyUsage:  []string{"invalid"},
		BasicConstraints: BasicConstraints{
			IsCA: false,
		},
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	err := ValidateTemplate(template, parent, "leaf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Fulcio leaf certificates must have codeSign extended key usage")
}

func TestValidateTemplateWithInvalidTimestamps(t *testing.T) {
	template := &CertificateTemplate{
		Subject: Subject{
			CommonName: "Test Leaf",
		},
		Issuer: Issuer{
			CommonName: "Test Root CA",
		},
		CertLifetime: "invalid",
		KeyUsage:     []string{"digitalSignature"},
		ExtKeyUsage:  []string{"CodeSigning"},
		BasicConstraints: BasicConstraints{
			IsCA: false,
		},
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	err := ValidateTemplate(template, parent, "leaf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certLife format: time: invalid duration \"invalid\"")
}

func TestValidateTemplateWithInvalidTimestampOrder(t *testing.T) {
	template := &CertificateTemplate{
		Subject: Subject{
			CommonName: "Test Leaf",
		},
		Issuer: Issuer{
			CommonName: "Test Root CA",
		},
		CertLifetime: "-8760h",
		KeyUsage:     []string{"digitalSignature"},
		ExtKeyUsage:  []string{"CodeSigning"},
		BasicConstraints: BasicConstraints{
			IsCA: false,
		},
	}

	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	err := ValidateTemplate(template, parent, "leaf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certLife must be positive")
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
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.pem")
	leafCertPath := filepath.Join(tmpDir, "leaf.pem")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"certLife": "4380h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"]
	}`
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{}

	err = CreateCertificates(mockSigner, KMSConfig{
		Type:      "awskms",
		RootKeyID: "root-key",
		LeafKeyID: "leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", intermediateTmplPath, intermediateCertPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing root template: certLife must be specified")
}

func TestCreateCertificatesWithInvalidLeafTemplate(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier)
		wantError string
	}{
		{
			name: "missing_timeStamping_extKeyUsage",
			setup: func(t *testing.T) (string, string, string, string, KMSConfig, signature.SignerVerifier) {
				tmpDir := t.TempDir()

				rootTmplPath := filepath.Join(tmpDir, "root-template.json")
				rootCertPath := filepath.Join(tmpDir, "root.crt")
				leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
				leafCertPath := filepath.Join(tmpDir, "leaf.crt")

				rootTemplate := `{
					"subject": {
						"commonName": "Test Root CA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z",
					"certLife": "8760h",
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {
						"isCA": true,
						"maxPathLen": 1
					}
				}`

				leafTemplate := `{
					"subject": {
						"commonName": "Test TSA"
					},
					"issuer": {
						"commonName": "Test Root CA"
					},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2024-12-31T23:59:59Z",
					"certLife": "8760h",
					"keyUsage": ["digitalSignature"],
					"extKeyUsage": ["CodeSigning"]
				}`

				err := os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
				require.NoError(t, err)
				err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
				require.NoError(t, err)

				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				mockSigner := &mockSignerVerifier{
					key: key,
					publicKeyFunc: func() (crypto.PublicKey, error) {
						return &key.PublicKey, nil
					},
					signMessageFunc: func(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
						msgBytes, err := io.ReadAll(message)
						if err != nil {
							return nil, err
						}
						h := crypto.SHA256.New()
						h.Write(msgBytes)
						digest := h.Sum(nil)
						return ecdsa.SignASN1(rand.Reader, key, digest)
					},
				}

				config := KMSConfig{
					Type:      "awskms",
					RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					Options:   map[string]string{"aws-region": "us-west-2"},
				}

				return rootTmplPath, rootCertPath, leafTmplPath, leafCertPath, config, mockSigner
			},
			wantError: "certificate notAfter time cannot be after parent's notAfter time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { InitKMS = originalInitKMS }()
			InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
				return &mockSignerVerifier{err: errors.New("test error")}, nil
			}

			rootTmpl, rootCert, leafTmpl, leafCert, config, signer := tt.setup(t)
			err := CreateCertificates(signer, config, rootTmpl, leafTmpl, rootCert, leafCert, "", "", "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesWithInvalidIntermediateKey(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()
	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if strings.Contains(config.IntermediateKeyID, "invalid-key") {
			return nil, fmt.Errorf("test error")
		}
		_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &mockSignerVerifier{err: errors.New("test error")}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
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
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Intermediate CA"
		},
		"certLife": "8760h",
		"keyUsage": ["digitalSignature"],
		"extensions": [
			{
				"id": "2.5.29.37",
				"critical": true,
				"value": "MCQwIgYDVR0lBBswGQYIKwYBBQUHAwgGDSsGAQQBgjcUAgICAf8="
			}
		]
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		err: errors.New("test error"),
	}

	config := KMSConfig{
		Type:              "awskms",
		RootKeyID:         "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		IntermediateKeyID: "invalid-key",
		LeafKeyID:         "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		Options:           map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "invalid-key", intermediateTmplPath, intermediateCertPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error getting root public key: test error")
}

func TestCreateCertificatesWithIntermediateErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
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
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0644)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		err: errors.New("test error"),
	}

	kmsConfig := KMSConfig{
		Type:              "mock",
		RootKeyID:         "root-key",
		IntermediateKeyID: "intermediate-key",
		LeafKeyID:         "leaf-key",
	}

	err = CreateCertificates(mockSigner, kmsConfig, rootTmplPath, "", "", "", "intermediate-key", intermediateTmplPath, intermediateCertPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test error")
}

func TestValidateTemplateWithDurationAndExtKeyUsage(t *testing.T) {
	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "valid_template_with_duration-based_validity",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Root CA",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: BasicConstraints{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
			parent:    nil,
			certType:  "root",
			wantError: "",
		},
		{
			name: "invalid_extended_key_usage",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"invalid"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "Fulcio leaf certificates must have codeSign extended key usage",
		},
		{
			name: "invalid_duration_format",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "invalid",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "invalid certLife format: time: invalid duration \"invalid\"",
		},
		{
			name: "negative_duration",
			template: &CertificateTemplate{
				Subject: Subject{
					CommonName: "Test Leaf",
				},
				Issuer: Issuer{
					CommonName: "Test Root CA",
				},
				CertLifetime: "-8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: BasicConstraints{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(24 * time.Hour),
			},
			certType:  "leaf",
			wantError: "certLife must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.template, tt.parent, tt.certType)
			if tt.wantError == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestCreateCertificatesWithoutIntermediate(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()
	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return &mockSignerVerifier{err: errors.New("test error")}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test TSA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "2190h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"]
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		err: errors.New("test error"),
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "test error")
}

func TestCreateCertificatesLeafErrors(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()
	InitKMS = func(_ context.Context, _ KMSConfig) (signature.SignerVerifier, error) {
		return &mockSignerVerifier{err: errors.New("test error")}, nil
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte("invalid json"), 0644)
	require.NoError(t, err)

	_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		err: errors.New("test error"),
	}

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		LeafKeyID: "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "test error")
}

func TestInitKMSWithDifferentProviders(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "aws_kms_missing_region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "alias/test-key",
				LeafKeyID: "alias/test-leaf-key",
			},
			wantError: "aws-region is required for AWS KMS",
		},
		{
			name: "gcp_kms_invalid_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-format",
				LeafKeyID: "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
				Options: map[string]string{
					"gcp-credentials-file": "/path/to/creds.json",
				},
			},
			wantError: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "azure_kms_missing_tenant_id",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=test-leaf-key;vault=test-vault",
				Options:   map[string]string{},
			},
			wantError: "azure-tenant-id is required for Azure KMS",
		},
		{
			name: "hashivault_kms_missing_token",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "transit/keys/test-key",
				LeafKeyID: "transit/keys/test-leaf-key",
				Options: map[string]string{
					"vault-address": "http://vault:8200",
				},
			},
			wantError: "vault-token is required for HashiVault KMS",
		},
		{
			name: "unsupported_kms_type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "test-key",
				LeafKeyID: "test-leaf-key",
			},
			wantError: "unsupported KMS type: unsupported",
		},
		{
			name: "azure_kms_invalid_key_format",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-format",
				LeafKeyID: "azurekms:name=test-leaf-key;vault=test-vault",
				Options: map[string]string{
					"azure-tenant-id": "test-tenant",
				},
			},
			wantError: "azurekms RootKeyID must start with 'azurekms:name='",
		},
		{
			name: "hashivault_kms_invalid_key_format",
			config: KMSConfig{
				Type:      "hashivault",
				RootKeyID: "invalid/format",
				LeafKeyID: "transit/keys/test-leaf-key",
				Options: map[string]string{
					"vault-token":   "test-token",
					"vault-address": "http://vault:8200",
				},
			},
			wantError: "hashivault RootKeyID must be in format: transit/keys/keyname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestWriteCertificateToFileAdditionalErrors(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		filename  string
		wantError string
	}{
		{
			name: "invalid_directory",
			cert: &x509.Certificate{
				Raw:  []byte("test"),
				IsCA: true,
			},
			filename:  "/nonexistent/directory/cert.pem",
			wantError: "failed to create file",
		},
		{
			name:      "nil_certificate",
			cert:      nil,
			filename:  "test.pem",
			wantError: "certificate cannot be nil",
		},
		{
			name: "empty_raw_data",
			cert: &x509.Certificate{
				IsCA: true,
			},
			filename:  "test.pem",
			wantError: "certificate has no raw data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteCertificateToFile(tt.cert, tt.filename)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestCreateCertificatesCreationFailure(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
		},
		cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
			return nil, nil, fmt.Errorf("crypto signer error")
		},
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "24h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "root-key",
		LeafKeyID: "leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting root crypto signer: crypto signer error")
}

func TestCreateCertificatesSuccessPath(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
		},
		cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
			return key, crypto.SHA256, nil
		},
	}

	InitKMS = func(_ context.Context, config KMSConfig) (signature.SignerVerifier, error) {
		if config.RootKeyID == "root-key" {
			return mockSigner, nil
		}
		if config.IntermediateKeyID == "intermediate-key" {
			return mockSigner, nil
		}
		if config.LeafKeyID == "leaf-key" {
			return mockSigner, nil
		}
		return nil, fmt.Errorf("unexpected key ID")
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
	intermediateCertPath := filepath.Join(tmpDir, "intermediate.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	intermediateTemplate := `{
		"subject": {
			"commonName": "Test Intermediate CA",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "4380h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf",
			"organization": ["Test Org"],
			"country": ["US"]
		},
		"issuer": {
			"commonName": "Test Intermediate CA"
		},
		"certLife": "24h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(intermediateTmplPath, []byte(intermediateTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	config := KMSConfig{
		Type:              "awskms",
		RootKeyID:         "root-key",
		IntermediateKeyID: "intermediate-key",
		LeafKeyID:         "leaf-key",
		Options:           map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "intermediate-key", intermediateTmplPath, intermediateCertPath)
	require.NoError(t, err)

	_, err = os.Stat(rootCertPath)
	require.NoError(t, err)
	_, err = os.Stat(intermediateCertPath)
	require.NoError(t, err)
	_, err = os.Stat(leafCertPath)
	require.NoError(t, err)
}

func TestCreateCertificatesInvalidSigner(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	mockSigner := &mockSignerVerifier{
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return nil, fmt.Errorf("signer does not implement CryptoSigner")
		},
		cryptoSignerFunc: nil,
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "24h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "root-key",
		LeafKeyID: "leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer does not implement CryptoSigner")
}

func TestCreateCertificatesCryptoSignerFailure(t *testing.T) {
	defer func() { InitKMS = originalInitKMS }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockSigner := &mockSignerVerifier{
		key: key,
		publicKeyFunc: func() (crypto.PublicKey, error) {
			return &key.PublicKey, nil
		},
		cryptoSignerFunc: func(_ context.Context, _ func(error)) (crypto.Signer, crypto.SignerOpts, error) {
			return nil, nil, fmt.Errorf("crypto signer error")
		},
	}

	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	rootCertPath := filepath.Join(tmpDir, "root.crt")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	leafCertPath := filepath.Join(tmpDir, "leaf.crt")

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"certLife": "24h",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning", "TimeStamping"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0644)
	require.NoError(t, err)

	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0644)
	require.NoError(t, err)

	config := KMSConfig{
		Type:      "awskms",
		RootKeyID: "root-key",
		LeafKeyID: "leaf-key",
		Options:   map[string]string{"aws-region": "us-west-2"},
	}

	err = CreateCertificates(mockSigner, config, rootTmplPath, leafTmplPath, rootCertPath, leafCertPath, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting root crypto signer: crypto signer error")
}
