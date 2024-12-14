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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/kms/apiv1"
)

type mockKMSProvider struct {
	name    string
	keys    map[string]*ecdsa.PrivateKey
	signers map[string]crypto.Signer
}

func newMockKMSProvider() *mockKMSProvider {
	m := &mockKMSProvider{
		name:    "test",
		keys:    make(map[string]*ecdsa.PrivateKey),
		signers: make(map[string]crypto.Signer),
	}

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m.keys["root-key"] = rootKey
	m.keys["intermediate-key"] = intermediateKey
	m.keys["leaf-key"] = leafKey

	return m
}

func (m *mockKMSProvider) CreateKey(*apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockKMSProvider) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	keyName := req.SigningKey
	if strings.HasPrefix(keyName, "arn:aws:kms:") {
		parts := strings.Split(keyName, "/")
		if len(parts) > 0 {
			keyName = parts[len(parts)-1]
		}
	}

	key, ok := m.keys[keyName]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.SigningKey)
	}
	m.signers[keyName] = key
	return key, nil
}

func (m *mockKMSProvider) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	key, ok := m.keys[req.Name]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.Name)
	}
	return key.Public(), nil
}

func (m *mockKMSProvider) Close() error {
	return nil
}

type mockInvalidKMS struct {
	apiv1.KeyManager
}

func (m *mockInvalidKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	return nil, fmt.Errorf("invalid KMS configuration: unsupported KMS type")
}

func (m *mockInvalidKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("invalid KMS configuration: unsupported KMS type")
}

func (m *mockInvalidKMS) Close() error {
	return nil
}

func TestParseTemplate(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cert-template-*.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpl, err := ParseTemplate(tmpFile.Name(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Subject.CommonName != "Test CA" {
		t.Errorf("got %v, want Test CA", tmpl.Subject.CommonName)
	}
	if !tmpl.IsCA {
		t.Errorf("got %v, want true", tmpl.IsCA)
	}
	if tmpl.MaxPathLen != 0 {
		t.Errorf("got %v, want 0", tmpl.MaxPathLen)
	}
}

func TestCreateCertificates(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) (string, KMSConfig, apiv1.KeyManager)
		wantError string
	}{
		{
			name: "successful certificate creation",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": false},
					"extKeyUsage": ["CodeSigning"],
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "awskms",
					Region:    "us-west-2",
					RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
		},
		{
			name: "invalid template path",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				config := KMSConfig{
					Type:      "awskms",
					Region:    "us-west-2",
					RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error parsing root template",
		},
		{
			name: "invalid KMS configuration",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
					"subject": {"commonName": "Test Root CA"},
					"issuer": {"commonName": "Test Root CA"},
					"keyUsage": ["certSign", "crlSign"],
					"basicConstraints": {"isCA": true, "maxPathLen": 1},
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
					"subject": {"commonName": "Test Leaf"},
					"keyUsage": ["digitalSignature"],
					"basicConstraints": {"isCA": false},
					"extKeyUsage": ["CodeSigning"],
					"notBefore": "2024-01-01T00:00:00Z",
					"notAfter": "2025-01-01T00:00:00Z"
				}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "invalid",
					RootKeyID: "test-key",
					LeafKeyID: "leaf-key",
				}

				return tmpDir, config, &mockInvalidKMS{}
			},
			wantError: "invalid KMS configuration: unsupported KMS type",
		},
		{
			name: "with intermediate certificate",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {"commonName": "Test Root CA"},
						"issuer": {"commonName": "Test Root CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 1},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
						"subject": {"commonName": "Test Intermediate CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 0},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write intermediate template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
						"subject": {"commonName": "Test Leaf"},
						"keyUsage": ["digitalSignature"],
						"basicConstraints": {"isCA": false},
						"extKeyUsage": ["CodeSigning"],
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:              "awskms",
					Region:            "us-west-2",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
		},
		{
			name: "invalid intermediate template",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {"commonName": "Test Root CA"},
						"issuer": {"commonName": "Test Root CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 1},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
						"subject": {"commonName": "Test Leaf"},
						"keyUsage": ["digitalSignature"],
						"basicConstraints": {"isCA": false},
						"extKeyUsage": ["CodeSigning"],
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:              "awskms",
					Region:            "us-west-2",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/intermediate-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error parsing intermediate template",
		},
		{
			name: "invalid intermediate key",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {"commonName": "Test Root CA"},
						"issuer": {"commonName": "Test Root CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 1},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				intermediateTemplate := filepath.Join(tmpDir, "intermediate.json")
				err = os.WriteFile(intermediateTemplate, []byte(`{
						"subject": {"commonName": "Test Intermediate CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 0},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write intermediate template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
						"subject": {"commonName": "Test Leaf"},
						"keyUsage": ["digitalSignature"],
						"basicConstraints": {"isCA": false},
						"extKeyUsage": ["CodeSigning"],
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:              "awskms",
					Region:            "us-west-2",
					RootKeyID:         "arn:aws:kms:us-west-2:123456789012:key/root-key",
					IntermediateKeyID: "arn:aws:kms:us-west-2:123456789012:key/nonexistent-key",
					LeafKeyID:         "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error creating intermediate signer",
		},
		{
			name: "error creating root certificate",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {},
						"issuer": {}
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				config := KMSConfig{
					Type:      "awskms",
					Region:    "us-west-2",
					RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error parsing root template: notBefore and notAfter times must be specified",
		},
		{
			name: "error creating leaf certificate",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {"commonName": "Test Root CA"},
						"issuer": {"commonName": "Test Root CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 1},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
						"subject": {},
						"issuer": {}
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "awskms",
					Region:    "us-west-2",
					RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error parsing leaf template: notBefore and notAfter times must be specified",
		},
		{
			name: "error writing certificates",
			setup: func(t *testing.T) (string, KMSConfig, apiv1.KeyManager) {
				tmpDir, err := os.MkdirTemp("", "cert-test-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				rootTemplate := filepath.Join(tmpDir, "root.json")
				err = os.WriteFile(rootTemplate, []byte(`{
						"subject": {"commonName": "Test Root CA"},
						"issuer": {"commonName": "Test Root CA"},
						"keyUsage": ["certSign", "crlSign"],
						"basicConstraints": {"isCA": true, "maxPathLen": 1},
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write root template: %v", err)
				}

				leafTemplate := filepath.Join(tmpDir, "leaf.json")
				err = os.WriteFile(leafTemplate, []byte(`{
						"subject": {"commonName": "Test Leaf"},
						"keyUsage": ["digitalSignature"],
						"basicConstraints": {"isCA": false},
						"extKeyUsage": ["CodeSigning"],
						"notBefore": "2024-01-01T00:00:00Z",
						"notAfter": "2025-01-01T00:00:00Z"
					}`), 0600)
				if err != nil {
					t.Fatalf("Failed to write leaf template: %v", err)
				}

				config := KMSConfig{
					Type:      "awskms",
					Region:    "us-west-2",
					RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/root-key",
					LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				}

				outDir := filepath.Join(tmpDir, "out")
				err = os.MkdirAll(outDir, 0444)
				if err != nil {
					t.Fatalf("Failed to create output directory: %v", err)
				}

				return tmpDir, config, newMockKMSProvider()
			},
			wantError: "error writing root certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, config, kms := tt.setup(t)
			defer os.RemoveAll(tmpDir)

			outDir := filepath.Join(tmpDir, "out")
			err := os.MkdirAll(outDir, 0755)
			if err != nil {
				t.Fatalf("Failed to create output directory: %v", err)
			}

			err = CreateCertificates(kms, config,
				filepath.Join(tmpDir, "root.json"),
				filepath.Join(tmpDir, "leaf.json"),
				filepath.Join(outDir, "root.crt"),
				filepath.Join(outDir, "leaf.crt"),
				config.IntermediateKeyID,
				filepath.Join(tmpDir, "intermediate.json"),
				filepath.Join(outDir, "intermediate.crt"))

			if tt.wantError != "" {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWriteCertificateToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-write-test-*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				content, err := os.ReadFile(tt.path)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				block, _ := pem.Decode(content)
				if block == nil {
					t.Errorf("failed to decode PEM block")
				}
				if block.Type != "CERTIFICATE" {
					t.Errorf("got %v, want CERTIFICATE", block.Type)
				}
			}
		})
	}
}

func verifyIntermediateChain(rootPath, intermediatePath, leafPath string) error {
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

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func loadCertificate(t *testing.T, path string) *x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}
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
			wantErrMsg: "must start with 'projects/'",
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
			wantErrMsg: "azurekms RootKeyID must contain ';vault=' parameter",
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
		{
			name: "aws_kms_invalid_arn_format",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-west-2:invalid",
			},
			wantErr:    true,
			wantErrMsg: "invalid AWS KMS ARN format for RootKeyID",
		},
		{
			name: "aws_kms_region_mismatch",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			},
			wantErr:    true,
			wantErrMsg: "region in ARN (us-east-1) does not match configured region (us-west-2)",
		},
		{
			name: "aws_kms_empty_alias",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "alias/",
			},
			wantErr:    true,
			wantErrMsg: "alias name cannot be empty for RootKeyID",
		},
		{
			name: "azure_kms_empty_key_name",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr:    true,
			wantErrMsg: "key name cannot be empty for RootKeyID",
		},
		{
			name: "azure_kms_empty_vault_name",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantErr:    true,
			wantErrMsg: "vault name cannot be empty for RootKeyID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErrMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tests := []struct {
		name string
		path string

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
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return f.Name()
			},
			wantError: "must have .json extension",
		},
		{
			name: "invalid JSON",
			path: "invalid.json",
			setup: func() string {
				f, err := os.CreateTemp("", "template*.json")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = os.WriteFile(f.Name(), []byte("invalid json"), 0600)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return f.Name()
			},
			wantError: "invalid JSON",
		},
		{
			name: "valid JSON template",
			path: "valid.json",
			setup: func() string {
				f, err := os.CreateTemp("", "template*.json")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				err = os.WriteFile(f.Name(), []byte(`{"key": "value"}`), 0600)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
			name: "missing_required_components",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project",
			},
			wantError: "gcpkms RootKeyID must contain '/locations/'",
		},
		{
			name: "valid_GCP_key_format",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
			},
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKMSConfig(tt.config)
			if tt.wantError != "" {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
			wantError: "azurekms RootKeyID must contain ';vault=' parameter",
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
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
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
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestInitKMS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kms-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	credsFile := filepath.Join(tmpDir, "test-credentials.json")
	err = os.WriteFile(credsFile, []byte(fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "test-key-id",
		"private_key": %q,
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id": "123456789",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test@test-project.iam.gserviceaccount.com"
	}`, string(privKeyPEM))), 0600)
	if err != nil {
		t.Fatalf("Failed to write credentials file: %v", err)
	}

	ctx := context.Background()
	tests := []struct {
		name      string
		config    KMSConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid AWS KMS config",
			config: KMSConfig{
				Type:      "awskms",
				Region:    "us-west-2",
				RootKeyID: "arn:aws:kms:us-west-2:123456789012:key/test-key",
				LeafKeyID: "arn:aws:kms:us-west-2:123456789012:key/leaf-key",
				Options:   map[string]string{},
			},
			wantError: false,
		},
		{
			name: "valid GCP KMS config",
			config: KMSConfig{
				Type:      "gcpkms",
				RootKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				LeafKeyID: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/leaf-key/cryptoKeyVersions/1",
				Options: map[string]string{
					"credentials-file": credsFile,
				},
			},
			wantError: false,
		},
		{
			name: "valid Azure KMS config",
			config: KMSConfig{
				Type:      "azurekms",
				RootKeyID: "azurekms:name=test-key;vault=test-vault",
				LeafKeyID: "azurekms:name=leaf-key;vault=test-vault",
				Options: map[string]string{
					"tenant-id": "test-tenant",
				},
			},
			wantError: false,
		},
		{
			name: "invalid KMS type",
			config: KMSConfig{
				Type:      "invalid",
				RootKeyID: "test-key",
				LeafKeyID: "leaf-key",
			},
			wantError: true,
			errMsg:    "invalid KMS configuration: unsupported KMS type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := InitKMS(ctx, tt.config)
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				if km != nil {
					t.Error("expected nil KMS but got non-nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if km == nil {
					t.Error("expected non-nil KMS but got nil")
				}
			}
		})
	}
}
