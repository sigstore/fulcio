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
	"crypto/x509/pkix"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTemplateFields(t *testing.T) {
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
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "subject.commonName cannot be empty",
		},
		{
			name: "missing issuer common name for root",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test CA"},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
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
				}{CommonName: "Test CA"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test CA"},
				KeyUsage: []string{},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "CA certificate must specify at least one key usage",
		},
		{
			name: "CA without certSign usage",
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
				KeyUsage: []string{"crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "CA certificate must have certSign key usage",
		},
		{
			name: "leaf with certSign usage",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Leaf"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test CA"},
				KeyUsage:    []string{"certSign", "digitalSignature"},
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
			},
			certType:  "leaf",
			wantError: "leaf certificate cannot have certSign key usage",
		},
		{
			name: "invalid_notBefore_format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test"},
				NotBefore: "invalid",
				NotAfter:  "2024-01-01T00:00:00Z",
			},
			certType:  "root",
			wantError: "invalid notBefore time format",
		},
		{
			name: "invalid_notAfter_format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test"},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "invalid",
			},
			certType:  "root",
			wantError: "invalid notAfter time format",
		},
		{
			name: "NotBefore after NotAfter",
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
				NotBefore: "2025-01-01T00:00:00Z",
				NotAfter:  "2024-01-01T00:00:00Z",
				KeyUsage:  []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
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

func TestParseTemplateErrors(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError string
	}{
		{
			name:      "invalid JSON",
			content:   `{"invalid": json}`,
			wantError: "invalid character",
		},
		{
			name: "missing time fields",
			content: `{
				"subject": {
					"commonName": "Test"
				}
			}`,
			wantError: "notBefore and notAfter times must be specified",
		},
		{
			name: "invalid time format",
			content: `{
				"subject": {
					"commonName": "Test"
				},
				"notBefore": "invalid",
				"notAfter": "2024-01-01T00:00:00Z"
			}`,
			wantError: "invalid notBefore time format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "cert-template-*.json")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			err = os.WriteFile(tmpFile.Name(), []byte(tt.content), 0600)
			require.NoError(t, err)

			_, err = ParseTemplate(tmpFile.Name(), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}

	// Test non-existent file
	_, err := ParseTemplate("nonexistent.json", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error reading template file")
}

func TestInvalidCertificateType(t *testing.T) {
	tmpl := &CertificateTemplate{
		Subject: struct {
			Country            []string `json:"country,omitempty"`
			Organization       []string `json:"organization,omitempty"`
			OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
			CommonName         string   `json:"commonName"`
		}{CommonName: "Test"},
		NotBefore: "2024-01-01T00:00:00Z",
		NotAfter:  "2025-01-01T00:00:00Z",
	}

	err := ValidateTemplate(tmpl, nil, "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate type")
}

func TestContainsExtKeyUsage(t *testing.T) {
	assert.False(t, containsExtKeyUsage(nil, "CodeSigning"), "empty list should return false")
	assert.False(t, containsExtKeyUsage([]string{}, "CodeSigning"), "empty list should return false")
	assert.True(t, containsExtKeyUsage([]string{"CodeSigning"}, "CodeSigning"), "should find matching usage")
	assert.False(t, containsExtKeyUsage([]string{"OtherUsage"}, "CodeSigning"), "should not find non-matching usage")
}

// Helper function to check if an extended key usage is present
func containsExtKeyUsage(usages []string, target string) bool {
	for _, usage := range usages {
		if usage == target {
			return true
		}
	}
	return false
}

func TestCreateCertificateFromTemplate(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		wantError bool
	}{
		{
			name: "valid leaf certificate",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					Country:            []string{"US"},
					Organization:       []string{"Test Org"},
					OrganizationalUnit: []string{"Test Unit"},
					CommonName:         "Test Leaf",
				},
				NotBefore:   "2024-01-01T00:00:00Z",
				NotAfter:    "2025-01-01T00:00:00Z",
				KeyUsage:    []string{"digitalSignature"},
				ExtKeyUsage: []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
			},
			wantError: false,
		},
		{
			name: "valid root certificate",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Root"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test Root"},
				NotBefore: "2024-01-01T00:00:00Z",
				NotAfter:  "2025-01-01T00:00:00Z",
				KeyUsage:  []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
			wantError: false,
		},
		{
			name: "invalid time format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test"},
				NotBefore: "invalid",
				NotAfter:  "2025-01-01T00:00:00Z",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := CreateCertificateFromTemplate(tt.tmpl, tt.parent)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify the certificate fields
			assert.Equal(t, tt.tmpl.Subject.CommonName, cert.Subject.CommonName)
			assert.Equal(t, tt.tmpl.Subject.Country, cert.Subject.Country)
			assert.Equal(t, tt.tmpl.Subject.Organization, cert.Subject.Organization)
			assert.Equal(t, tt.tmpl.Subject.OrganizationalUnit, cert.Subject.OrganizationalUnit)
			assert.Equal(t, tt.tmpl.BasicConstraints.IsCA, cert.IsCA)

			if tt.tmpl.BasicConstraints.IsCA {
				assert.Equal(t, tt.tmpl.BasicConstraints.MaxPathLen, cert.MaxPathLen)
			}
		})
	}
}

func TestSetKeyUsagesAndExtKeyUsages(t *testing.T) {
	cert := &x509.Certificate{}

	// Test key usages
	SetKeyUsages(cert, []string{"certSign", "crlSign", "digitalSignature"})
	assert.True(t, cert.KeyUsage&x509.KeyUsageCertSign != 0)
	assert.True(t, cert.KeyUsage&x509.KeyUsageCRLSign != 0)
	assert.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0)

	// Test extended key usages
	SetExtKeyUsages(cert, []string{"CodeSigning"})
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)

	// Test with empty usages
	newCert := &x509.Certificate{}
	SetKeyUsages(newCert, nil)
	SetExtKeyUsages(newCert, nil)
	assert.Equal(t, x509.KeyUsage(0), newCert.KeyUsage)
	assert.Empty(t, newCert.ExtKeyUsage)
}
