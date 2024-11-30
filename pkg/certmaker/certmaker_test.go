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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"
)

// mockKMS provides an in-memory KMS for testing
type mockKMS struct {
	keys    map[string]*ecdsa.PrivateKey
	signers map[string]crypto.Signer
}

func newMockKMS() *mockKMS {
	m := &mockKMS{
		keys:    make(map[string]*ecdsa.PrivateKey),
		signers: make(map[string]crypto.Signer),
	}

	// Pre-create test keys
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m.keys["root-key"] = rootKey
	m.keys["intermediate-key"] = intermediateKey
	m.keys["leaf-key"] = leafKey

	return m
}

func (m *mockKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	key, ok := m.keys[req.SigningKey]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.SigningKey)
	}
	m.signers[req.SigningKey] = key
	return key, nil
}

func (m *mockKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	key, ok := m.keys[req.Name]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.Name)
	}
	return key.Public(), nil
}

func (m *mockKMS) Close() error {
	return nil
}

func (m *mockKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("CreateKey is not supported in mockKMS")
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

		verifyIntermediateChain(t, rootCertPath, intermediateCertPath, leafCertPath)
	})
}

// TestWriteCertificateToFile tests PEM file writing
func TestWriteCertificateToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-write-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	km := newMockKMS()
	signer, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "root-key",
	})
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
	}

	cert, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	require.NoError(t, err)

	testFile := filepath.Join(tmpDir, "test-cert.pem")
	err = WriteCertificateToFile(cert, testFile)
	require.NoError(t, err)

	content, err := os.ReadFile(testFile)
	require.NoError(t, err)

	block, _ := pem.Decode(content)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "Test Cert", parsedCert.Subject.CommonName)
}

func verifyIntermediateChain(t *testing.T, rootPath, intermediatePath, leafPath string) {
	root := loadCertificate(t, rootPath)
	intermediate := loadCertificate(t, intermediatePath)
	leaf := loadCertificate(t, leafPath)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediate)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	require.NoError(t, err)
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
		name    string
		config  KMSConfig
		wantErr bool
	}{
		{
			name: "valid aws config",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-west-2:account-id:key/key-id",
				LeafKeyID: "arn:aws:kms:us-west-2:account-id:key/leaf-key-id",
			},
			wantErr: false,
		},
		{
			name: "valid gcp config",
			config: KMSConfig{
				Type:      "cloudkms",
				RootKeyID: "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/key-id",
				LeafKeyID: "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/leaf-key-id",
				Options: map[string]string{
					"credentials-file": "/path/to/credentials.json",
				},
			},
			wantErr: false,
		},
		{
			name: "valid azure config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=root-key;vault=test-vault",
				LeafKeyID: "azurekms:name=leaf-key;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr: false,
		},
		{
			name: "missing aws region",
			config: KMSConfig{
				Type:      "awskms",
				RootKeyID: "arn:aws:kms:us-west-2:account-id:key/key-id",
			},
			wantErr: true,
		},
		{
			name: "invalid gcp key format",
			config: KMSConfig{
				Type:      "cloudkms",
				RootKeyID: "invalid-format",
			},
			wantErr: true,
		},
		{
			name: "missing key IDs",
			config: KMSConfig{
				Type: "azurekms",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr: true,
		},
		{
			name: "valid aws config with intermediate",
			config: KMSConfig{
				Type:              "awskms",
				Region:            "us-west-2",
				RootKeyID:         "arn:aws:kms:us-west-2:account-id:key/key-id",
				IntermediateKeyID: "arn:aws:kms:us-west-2:account-id:key/intermediate-key-id",
				LeafKeyID:         "arn:aws:kms:us-west-2:account-id:key/leaf-key-id",
			},
			wantErr: false,
		},
		{
			name: "valid gcp config with intermediate",
			config: KMSConfig{
				Type:              "cloudkms",
				RootKeyID:         "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/key-id",
				IntermediateKeyID: "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/intermediate-key-id",
				LeafKeyID:         "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/leaf-key-id",
			},
			wantErr: false,
		},
		{
			name: "valid azure config with intermediate",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "azurekms:name=root-key;vault=test-vault",
				IntermediateKeyID: "azurekms:name=intermediate-key;vault=test-vault",
				LeafKeyID:         "azurekms:name=leaf-key;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid intermediate key format",
			config: KMSConfig{
				Type:              "cloudkms",
				RootKeyID:         "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/key-id",
				IntermediateKeyID: "invalid-format",
				LeafKeyID:         "projects/project-id/locations/global/keyRings/ring-id/cryptoKeys/leaf-key-id",
			},
			wantErr: true,
		},
		{
			name: "invalid aws intermediate key format",
			config: KMSConfig{
				Type:              "awskms",
				Region:            "us-west-2",
				RootKeyID:         "arn:aws:kms:us-west-2:account-id:key/key-id",
				IntermediateKeyID: "invalid-format",
				LeafKeyID:         "arn:aws:kms:us-west-2:account-id:key/leaf-key-id",
			},
			wantErr: true,
		},
		{
			name: "invalid azure intermediate key format",
			config: KMSConfig{
				Type:              "azurekms",
				RootKeyID:         "azurekms:name=root-key;vault=test-vault",
				IntermediateKeyID: "invalid:format",
				LeafKeyID:         "azurekms:name=leaf-key;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
