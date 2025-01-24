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

	validTemplate := `{
		"subject": {
			"commonName": "Test CA"
		},
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	invalidTemplate := `{
		"invalid": "json"
		"missing": "comma"
	}`

	validPath := filepath.Join(tmpDir, "valid.json")
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	err := os.WriteFile(validPath, []byte(validTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidPath, []byte(invalidTemplate), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		filename  string
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name:     "valid template",
			filename: validPath,
			parent:   nil,
			certType: "root",
		},
		{
			name:      "invalid template json",
			filename:  invalidPath,
			parent:    nil,
			certType:  "root",
			wantError: "invalid template JSON",
		},
		{
			name:      "nonexistent file",
			filename:  "nonexistent.json",
			parent:    nil,
			certType:  "root",
			wantError: "template not found at",
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
