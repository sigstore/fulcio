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
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
)

// mockKMS provides an in-memory KMS for testing
type mockKMS struct {
	keys map[string]crypto.Signer
}

func newMockKMS() *mockKMS {
	keys := make(map[string]crypto.Signer)
	// Create test keys
	for _, id := range []string{"root-key", "intermediate-key", "leaf-key"} {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		keys[id] = priv
	}
	return &mockKMS{keys: keys}
}

func (m *mockKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if signer, ok := m.keys[req.SigningKey]; ok {
		return signer, nil
	}
	return nil, fmt.Errorf("key not found: %s", req.SigningKey)
}

func (m *mockKMS) CreateKey(_ *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("CreateKey is not supported in mockKMS")
}

func (m *mockKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if signer, ok := m.keys[req.Name]; ok {
		return signer.Public(), nil
	}
	return nil, fmt.Errorf("key not found: %s", req.Name)
}

func (m *mockKMS) Close() error {
	return nil
}

// TestParseTemplate tests JSON template parsing
func TestParseTemplate(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cert-template-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	templateContent := `{
		"subject": {
			"commonName": "Test CA"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"keyUsage": [
			"certSign",
			"crlSign"
		],
		"extKeyUsage": [
			"CodeSigning"
		],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 0
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z"
	}`

	err = os.WriteFile(tmpFile.Name(), []byte(templateContent), 0600)
	require.NoError(t, err)

	tmpl, err := ParseTemplate(tmpFile.Name(), nil)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", tmpl.Subject.CommonName)
	assert.True(t, tmpl.IsCA)
	assert.Equal(t, 0, tmpl.MaxPathLen)
}

// TestCreateCertificates tests certificate chain creation
func TestCreateCertificates(t *testing.T) {
	rootContent := `{
		"subject": {
			"country": ["US"],
			"organization": ["Sigstore"],
			"organizationalUnit": ["Fulcio Root CA"],
			"commonName": "fulcio.sigstore.dev"
		},
		"issuer": {
			"commonName": "fulcio.sigstore.dev"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		},
		"keyUsage": [
			"certSign",
			"crlSign"
		]
	}`

	leafContent := `{
		"subject": {
			"country": ["US"],
			"organization": ["Sigstore"],
			"organizationalUnit": ["Fulcio"],
			"commonName": "fulcio.sigstore.dev"
		},
		"issuer": {
			"commonName": "fulcio.sigstore.dev"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2034-01-01T00:00:00Z",
		"basicConstraints": {
			"isCA": false
		},
		"keyUsage": [
			"digitalSignature"
		],
		"extKeyUsage": [
			"CodeSigning"
		]
	}`

	t.Run("Fulcio without intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-fulcio-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		km := newMockKMS()
		config := KMSConfig{
			Type:      "mockkms",
			RootKeyID: "root-key",
			LeafKeyID: "leaf-key",
			Options:   make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)

		err = os.WriteFile(leafTmplPath, []byte(leafContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, leafTmplPath,
			rootCertPath, leafCertPath,
			"", "", "")
		require.NoError(t, err)

		verifyDirectChain(t, rootCertPath, leafCertPath)
	})

	t.Run("Fulcio with intermediate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "cert-test-fulcio-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(tmpDir) })

		intermediateContent := `{
			"subject": {
				"country": ["US"],
				"organization": ["Sigstore"],
				"organizationalUnit": ["Fulcio Intermediate CA"],
				"commonName": "fulcio.sigstore.dev"
			},
			"issuer": {
				"commonName": "fulcio.sigstore.dev"
			},
			"notBefore": "2024-01-01T00:00:00Z",
			"notAfter": "2034-01-01T00:00:00Z",
			"basicConstraints": {
				"isCA": true,
				"maxPathLen": 0
			},
			"keyUsage": [
				"certSign",
				"crlSign"
			]
		}`

		km := newMockKMS()
		config := KMSConfig{
			Type:              "mockkms",
			RootKeyID:         "root-key",
			IntermediateKeyID: "intermediate-key",
			LeafKeyID:         "leaf-key",
			Options:           make(map[string]string),
		}

		rootTmplPath := filepath.Join(tmpDir, "root-template.json")
		leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
		intermediateTmplPath := filepath.Join(tmpDir, "intermediate-template.json")
		rootCertPath := filepath.Join(tmpDir, "root.pem")
		intermediateCertPath := filepath.Join(tmpDir, "intermediate.pem")
		leafCertPath := filepath.Join(tmpDir, "leaf.pem")

		err = os.WriteFile(rootTmplPath, []byte(rootContent), 0600)
		require.NoError(t, err)
		err = os.WriteFile(intermediateTmplPath, []byte(intermediateContent), 0600)
		require.NoError(t, err)
		err = os.WriteFile(leafTmplPath, []byte(leafContent), 0600)
		require.NoError(t, err)

		err = CreateCertificates(km, config,
			rootTmplPath, leafTmplPath,
			rootCertPath, leafCertPath,
			"intermediate-key", intermediateTmplPath, intermediateCertPath)
		require.NoError(t, err)

		verifyIntermediateChain(rootCertPath, intermediateCertPath, leafCertPath)
	})
}

// TestWriteCertificateToFile tests certificate file writing
func TestWriteCertificateToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-write-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a test certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}

	tests := []struct {
		name      string
		cert      *x509.Certificate
		path      string
		wantError bool
		errMsg    string
	}{
		{
			name: "valid certificate",
			cert: cert,
			path: filepath.Join(tmpDir, "test-root.pem"),
		},
		{
			name:      "invalid path",
			cert:      cert,
			path:      "/nonexistent/dir/cert.pem",
			wantError: true,
			errMsg:    "failed to create file",
		},
		{
			name:      "directory instead of file",
			cert:      cert,
			path:      tmpDir,
			wantError: true,
			errMsg:    "failed to create file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteCertificateToFile(tt.cert, tt.path)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				// Verify the file exists and contains a PEM block
				content, err := os.ReadFile(tt.path)
				require.NoError(t, err)
				block, _ := pem.Decode(content)
				require.NotNil(t, block)
				assert.Equal(t, "CERTIFICATE", block.Type)
			}
		})
	}
}

func verifyIntermediateChain(rootPath, intermediatePath, leafPath string) error {
	// Read certificates
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return fmt.Errorf("error reading root certificate: %w", err)
	}
	intermediatePEM, err := os.ReadFile(intermediatePath)
	if err != nil {
		return fmt.Errorf("error reading intermediate certificate: %w", err)
	}
	leafPEM, err := os.ReadFile(leafPath)
	if err != nil {
		return fmt.Errorf("error reading leaf certificate: %w", err)
	}

	// Parse certificates
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil {
		return fmt.Errorf("failed to decode root certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing root certificate: %w", err)
	}

	intermediateBlock, _ := pem.Decode(intermediatePEM)
	if intermediateBlock == nil {
		return fmt.Errorf("failed to decode intermediate certificate PEM")
	}
	intermediateCert, err := x509.ParseCertificate(intermediateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing intermediate certificate: %w", err)
	}

	leafBlock, _ := pem.Decode(leafPEM)
	if leafBlock == nil {
		return fmt.Errorf("failed to decode leaf certificate PEM")
	}
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing leaf certificate: %w", err)
	}

	// Create certificate pools
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	// Verify the chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	_, err = leafCert.Verify(opts)
	return err
}

func verifyDirectChain(t *testing.T, rootPath, leafPath string) {
	root := loadCertificate(t, rootPath)
	leaf := loadCertificate(t, leafPath)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	require.NoError(t, err)
}

func loadCertificate(t *testing.T, path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestValidateKMSConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     KMSConfig
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "empty_config",
			config:     KMSConfig{},
			wantErr:    true,
			wantErrMsg: "KMS type cannot be empty",
		},
		{
			name: "missing_key_ids",
			config: KMSConfig{
				Type:   "awskms",
				Region: "us-west-2",
			},
			wantErr:    true,
			wantErrMsg: "at least one of RootKeyID or LeafKeyID must be specified",
		},
		{
			name: "aws_kms_missing_region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-1234567890ab",
			},
			wantErr:    true,
			wantErrMsg: "region is required for AWS KMS",
		},
		{
			name: "aws_kms_invalid_root_key_format",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "invalid-key-format",
			},
			wantErr:    true,
			wantErrMsg: "awskms RootKeyID must start with 'arn:aws:kms:' or 'alias/'",
		},
		{
			name: "gcp_kms_invalid_root_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-id",
			},
			wantErr:    true,
			wantErrMsg: "gcpkms RootKeyID must start with 'projects/'",
		},
		{
			name: "azure_kms_missing_tenant_id",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey",
				Options: map[string]string{
					"vault": "test-vault",
				},
			},
			wantErr:    true,
			wantErrMsg: "tenant-id is required for Azure KMS",
		},
		{
			name: "azure_kms_missing_vault",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr:    true,
			wantErrMsg: "vault name is required for Azure Key Vault",
		},
		{
			name: "azure_kms_missing_options",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey",
			},
			wantErr:    true,
			wantErrMsg: "options map is required for Azure KMS",
		},
		{
			name: "unsupported_kms_type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "key-id",
			},
			wantErr:    true,
			wantErrMsg: "unsupported KMS type: unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateTemplate tests template validation
func TestValidateTemplate(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "valid root CA",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test CA"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test CA"},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
				KeyUsage:  []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType: "root",
		},
		{
			name: "missing subject common name",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				KeyUsage: []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: true,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "subject.commonName cannot be empty",
		},
		{
			name: "missing issuer common name",
			tmpl: &CertificateTemplate{
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
				}{},
				KeyUsage: []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: true,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "issuer.commonName cannot be empty for root certificate",
		},
		{
			name: "CA without key usage",
			tmpl: &CertificateTemplate{
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
				KeyUsage: []string{},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: true,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "CA certificate must specify at least one key usage",
		},
		{
			name: "leaf without code signing",
			tmpl: &CertificateTemplate{
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
					CommonName: "Test Root CA",
				},
				KeyUsage: []string{"digitalSignature"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
			},
			certType:  "leaf",
			wantError: "Fulcio leaf certificates must have codeSign extended key usage",
		},
		{
			name: "valid leaf certificate",
			tmpl: &CertificateTemplate{
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
					CommonName: "Test Root CA",
				},
				NotBefore:   "2024-01-01T00:00:00Z",
				NotAfter:    "2025-01-01T00:00:00Z",
				KeyUsage:    []string{"digitalSignature"},
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
			},
			certType: "leaf",
		},
		{
			name: "leaf without parent",
			tmpl: &CertificateTemplate{
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
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "leaf",
			parent:    nil,
			wantError: "parent certificate is required for non-root certificates",
		},
		{
			name: "invalid key usage",
			tmpl: &CertificateTemplate{
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
				KeyUsage: []string{"invalidKeyUsage"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: true,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "CA certificate must have certSign key usage",
		},
		{
			name: "invalid extended key usage",
			tmpl: &CertificateTemplate{
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
					CommonName: "Test Root CA",
				},
				KeyUsage:    []string{"digitalSignature"},
				ExtKeyUsage: []string{"invalidExtKeyUsage"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
			},
			certType:  "leaf",
			wantError: "Fulcio leaf certificates must have codeSign extended key usage",
		},
		{
			name: "valid intermediate certificate",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test Intermediate CA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				KeyUsage: []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 0,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				IsCA:       true,
				MaxPathLen: 1,
			},
			certType: "intermediate",
		},
		{
			name: "intermediate with wrong MaxPathLen",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					CommonName: "Test Intermediate CA",
				},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{
					CommonName: "Test Root CA",
				},
				KeyUsage: []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 2,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			certType:  "intermediate",
			parent:    &x509.Certificate{Subject: pkix.Name{CommonName: "Test Root CA"}, IsCA: true},
			wantError: "intermediate CA MaxPathLen must be 0",
		},
		{
			name: "NotBefore after NotAfter",
			tmpl: &CertificateTemplate{
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
				NotBefore: "2025-01-01T00:00:00Z",
				NotAfter:  "2024-01-01T00:00:00Z",
				KeyUsage:  []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: true,
				},
			},
			certType:  "root",
			wantError: "NotBefore time must be before NotAfter time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.tmpl, tt.parent, tt.certType)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTemplateKeyUsageCombinations(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "leaf with certSign usage",
			tmpl: &CertificateTemplate{
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
				NotBefore:   "2024-01-01T00:00:00Z",
				NotAfter:    "2025-01-01T00:00:00Z",
				KeyUsage:    []string{"certSign", "digitalSignature"},
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
			},
			certType:  "leaf",
			parent:    &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}},
			wantError: "leaf certificate cannot have certSign key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.tmpl, tt.parent, tt.certType)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateLeafCertificateKeyUsage(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		wantError bool
		errMsg    string
	}{
		{
			name: "leaf with certSign usage",
			tmpl: &CertificateTemplate{
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
				KeyUsage:    []string{"certSign", "digitalSignature"},
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA: false,
				},
				NotBefore: "2021-01-01T00:00:00Z",
				NotAfter:  "2022-01-01T00:00:00Z",
			},
			parent:    &x509.Certificate{Subject: pkix.Name{CommonName: "Test CA"}},
			wantError: true,
			errMsg:    "leaf certificate cannot have certSign key usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.tmpl, tt.parent, "leaf")
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		setup     func() string
		wantError string
	}{
		{
			name:      "nonexistent file",
			path:      "/nonexistent/template.json",
			wantError: "template not found",
		},
		{
			name: "wrong extension",
			path: "template.txt",
			setup: func() string {
				f, err := os.CreateTemp("", "template.txt")
				require.NoError(t, err)
				return f.Name()
			},
			wantError: "must have .json extension",
		},
		{
			name: "invalid JSON",
			path: "invalid.json",
			setup: func() string {
				f, err := os.CreateTemp("", "template*.json")
				require.NoError(t, err)
				err = os.WriteFile(f.Name(), []byte("invalid json"), 0600)
				require.NoError(t, err)
				return f.Name()
			},
			wantError: "invalid JSON",
		},
		{
			name: "valid JSON template",
			path: "valid.json",
			setup: func() string {
				f, err := os.CreateTemp("", "template*.json")
				require.NoError(t, err)
				err = os.WriteFile(f.Name(), []byte(`{"key": "value"}`), 0600)
				require.NoError(t, err)
				return f.Name()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.setup != nil {
				path = tt.setup()
				defer os.Remove(path)
			}

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

func TestGCPKMSValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "invalid_root_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "invalid-key-id",
			},
			wantError: "must start with 'projects/'",
		},
		{
			name: "missing_locations_in_key_path",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project",
			},
			wantError: "invalid gcpkms key format",
		},
		{
			name: "valid_GCP_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
			},
			wantError: "",
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

func TestAzureKMSValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "missing options map",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey;vault=myvault",
			},
			wantError: "options map is required",
		},
		{
			name: "missing tenant id",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey;vault=myvault",
				Options:   map[string]string{},
			},
			wantError: "tenant-id is required",
		},
		{
			name: "invalid key format",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "invalid-format",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: "must start with 'azurekms:name='",
		},
		{
			name: "missing vault name",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: "vault name is required",
		},
		{
			name: "valid config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=mykey;vault=myvault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
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

func TestInitKMSErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		config    KMSConfig
		wantError string
	}{
		{
			name: "empty config",
			config: KMSConfig{
				Type: "",
			},
			wantError: "KMS type cannot be empty",
		},
		{
			name: "unsupported KMS type",
			config: KMSConfig{
				Type:      "unsupported",
				RootKeyID: "key-id",
			},
			wantError: "unsupported KMS type",
		},
		{
			name: "missing required keys",
			config: KMSConfig{
				Type: "awskms",
			},
			wantError: "at least one of RootKeyID or LeafKeyID must be specified",
		},
		{
			name: "GCP KMS with nonexistent credentials file",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				Options: map[string]string{
					"credentials-file": "/nonexistent/credentials.json",
				},
			},
			wantError: "credentials file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InitKMS(ctx, tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}
