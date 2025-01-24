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

// Package certmaker provides template parsing and certificate generation functionality
// for creating X.509 certificates from JSON templates per RFC3161 standards.
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
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x509util"
)

func TestParseTemplate(t *testing.T) {
	tmpDir := t.TempDir()

	validTemplate := `{
		"subject": {
			"commonName": "{{ .Subject.CommonName }}"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	invalidTemplate := `{
		invalid json
	}`

	validPath := filepath.Join(tmpDir, "valid.json")
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	err := os.WriteFile(validPath, []byte(validTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidPath, []byte(invalidTemplate), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name       string
		filename   string
		parent     *x509.Certificate
		notAfter   time.Time
		publicKey  crypto.PublicKey
		commonName string
		wantError  string
	}{
		{
			name:       "valid template",
			filename:   validPath,
			parent:     nil,
			notAfter:   time.Now().Add(time.Hour * 24),
			publicKey:  key.Public(),
			commonName: "Test CA",
		},
		{
			name:       "invalid template",
			filename:   invalidPath,
			parent:     nil,
			notAfter:   time.Now().Add(time.Hour * 24),
			publicKey:  key.Public(),
			commonName: "Test CA",
			wantError:  "error parsing template: error unmarshaling certificate",
		},
		{
			name:       "nonexistent file",
			filename:   "nonexistent.json",
			parent:     nil,
			notAfter:   time.Now().Add(time.Hour * 24),
			publicKey:  key.Public(),
			commonName: "Test CA",
			wantError:  "input must be either a template string or template content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var content interface{}
			if tt.filename == "nonexistent.json" {
				content = struct{}{} // Use invalid type to trigger type error
			} else {
				// Read the file content for valid cases
				fileContent, err := os.ReadFile(tt.filename)
				if err != nil {
					t.Fatalf("failed to read test file: %v", err)
				}
				content = string(fileContent)
			}

			cert, err := ParseTemplate(content, tt.parent, tt.notAfter, tt.publicKey, tt.commonName)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
				assert.Equal(t, tt.commonName, cert.Subject.CommonName)
				assert.Equal(t, tt.publicKey, cert.PublicKey)
				assert.Equal(t, tt.notAfter, cert.NotAfter)
			}
		})
	}
}

func TestValidateTemplate(t *testing.T) {
	tmpDir := t.TempDir()

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
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
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning"],
		"basicConstraints": {
			"isCA": false
		}
	}`

	rootTmplPath := filepath.Join(tmpDir, "root.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf.json")
	err := os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Parent CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		PublicKey:             key.Public(),
	}

	tests := []struct {
		name      string
		filename  string
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name:     "valid root template",
			filename: rootTmplPath,
			parent:   nil,
			certType: "root",
		},
		{
			name:      "root with parent",
			filename:  rootTmplPath,
			parent:    parent,
			certType:  "root",
			wantError: "root certificate cannot have a parent",
		},
		{
			name:     "valid leaf template",
			filename: leafTmplPath,
			parent:   parent,
			certType: "leaf",
		},
		{
			name:      "leaf without parent",
			filename:  leafTmplPath,
			parent:    nil,
			certType:  "leaf",
			wantError: "leaf certificate must have a parent",
		},
		{
			name:      "invalid cert type",
			filename:  leafTmplPath,
			parent:    parent,
			certType:  "invalid",
			wantError: "invalid certificate type: invalid",
		},
		{
			name:      "nonexistent file",
			filename:  "nonexistent.json",
			parent:    parent,
			certType:  "leaf",
			wantError: "error reading template file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplate(tt.filename, tt.parent, tt.certType)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTemplatePath(t *testing.T) {
	tmpDir := t.TempDir()

	validTemplate := `{
		"subject": {
			"commonName": "Test CA"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		},
		"validity": {
			"notBefore": "{{ now }}",
			"notAfter": "{{ .NotAfter }}"
		}
	}`

	invalidTemplate := `{
		"subject": {
			"commonName": "Test CA",
		},
		invalid json
	}`

	validPath := filepath.Join(tmpDir, "valid.json")
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	wrongExtPath := filepath.Join(tmpDir, "wrong.txt")

	require.NoError(t, os.WriteFile(validPath, []byte(validTemplate), 0600))
	require.NoError(t, os.WriteFile(invalidPath, []byte(invalidTemplate), 0600))
	require.NoError(t, os.WriteFile(wrongExtPath, []byte(validTemplate), 0600))

	tests := []struct {
		name      string
		path      string
		wantError bool
		errMsg    string
	}{
		{
			name:      "valid template",
			path:      validPath,
			wantError: false,
		},
		{
			name:      "nonexistent file",
			path:      "nonexistent.json",
			wantError: true,
			errMsg:    "template not found at nonexistent.json",
		},
		{
			name:      "wrong file extension",
			path:      wrongExtPath,
			wantError: true,
			errMsg:    "template file must have .json extension",
		},
		{
			name:      "invalid JSON",
			path:      invalidPath,
			wantError: true,
			errMsg:    "invalid JSON in template file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplatePath(tt.path)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeterminePublicKeyAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		want      x509.PublicKeyAlgorithm
	}{
		{
			name:      "ECDSA key",
			publicKey: ecKey.Public(),
			want:      x509.ECDSA,
		},
		{
			name:      "RSA key",
			publicKey: rsaKey.Public(),
			want:      x509.RSA,
		},
		{
			name:      "Ed25519 key",
			publicKey: ed25519Key,
			want:      3, // x509.Ed25519
		},
		{
			name:      "Unknown key type",
			publicKey: struct{}{},
			want:      x509.ECDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePublicKeyAlgorithm(tt.publicKey)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetDefaultTemplate(t *testing.T) {
	tests := []struct {
		name      string
		certType  string
		wantError string
	}{
		{
			name:     "root template",
			certType: "root",
		},
		{
			name:     "intermediate template",
			certType: "intermediate",
		},
		{
			name:     "leaf template",
			certType: "leaf",
		},
		{
			name:      "invalid type",
			certType:  "invalid",
			wantError: "invalid certificate type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDefaultTemplate(tt.certType)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, got)

				err = x509util.ValidateTemplate([]byte(got))
				require.NoError(t, err)

				assert.Contains(t, got, "subject")
				assert.Contains(t, got, "keyUsage")
				assert.Contains(t, got, "basicConstraints")

				switch tt.certType {
				case "root", "intermediate":
					assert.Contains(t, got, `"isCA": true`)
				case "leaf":
					assert.Contains(t, got, `"isCA": false`)
				}
			}
		})
	}
}
