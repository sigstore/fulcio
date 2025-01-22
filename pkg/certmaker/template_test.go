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
	"strings"
	"testing"
	"time"

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
			name: "valid_root_CA",
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
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType: "root",
		},
		{
			name: "missing_subject_common_name",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{},
				CertLifetime: "8760h",
			},
			certType:  "root",
			wantError: "subject.commonName cannot be empty",
		},
		{
			name: "missing_issuer_common_name_for_root",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test CA"},
				CertLifetime: "8760h",
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType:  "root",
			wantError: "issuer.commonName cannot be empty for root certificate",
		},
		{
			name: "CA_without_key_usage",
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
				CertLifetime: "8760h",
			},
			certType:  "root",
			wantError: "CA certificate must specify at least one key usage",
		},
		{
			name: "CA_without_certSign_usage",
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
				CertLifetime: "8760h",
			},
			certType:  "root",
			wantError: "CA certificate must have certSign key usage",
		},
		{
			name: "leaf_with_certSign_usage",
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
				KeyUsage:     []string{"certSign", "digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				CertLifetime: "8760h",
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),
			},
			certType:  "leaf",
			wantError: "leaf certificate cannot have certSign key usage",
		},
		{
			name: "invalid_certLife_format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test"},
				CertLifetime: "1y",
			},
			certType:  "root",
			wantError: "invalid certLife format",
		},
		{
			name: "leaf_without_CodeSigning_usage",
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
				KeyUsage:     []string{"digitalSignature"},
				CertLifetime: "8760h",
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),
			},
			certType:  "leaf",
			wantError: "Fulcio leaf certificates must have codeSign extended key usage",
		},
		{
			name: "valid_intermediate_CA",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Intermediate CA"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test Root CA"},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 0,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 2), // 2 years
			},
			certType: "intermediate",
		},
		{
			name: "intermediate_with_wrong_MaxPathLen",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Intermediate CA"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test Root CA"},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{
					IsCA:       true,
					MaxPathLen: 1,
				},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test Root CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),
			},
			certType:  "intermediate",
			wantError: "intermediate CA MaxPathLen must be 0",
		},
		{
			name: "leaf_with_invalid_time_constraints",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Leaf"},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(time.Hour), // Parent's NotBefore is in the future
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),
			},
			certType:  "leaf",
			wantError: "certificate notBefore time cannot be before parent's notBefore time",
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
			name: "missing_time_fields",
			content: `{
				"subject": {
					"commonName": "Test CA"
				},
				"certLife": "",
				"keyUsage": ["certSign"]
			}`,
			wantError: "certLife must be specified",
		},
		{
			name: "invalid time format",
			content: `{
				"subject": {
					"commonName": "Test"
				},
				"certLife": "invalid"
			}`,
			wantError: "invalid certLife format",
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

	_, err := ParseTemplate("nonexistent.json", nil)
	if err == nil {
		t.Errorf("expected error, got nil")
	} else if !strings.Contains(err.Error(), "error reading template file") {
		t.Errorf("error %q should contain %q", err.Error(), "error reading template file")
	}
}

func TestInvalidCertificateType(t *testing.T) {
	tmpl := &CertificateTemplate{
		Subject: struct {
			Country            []string `json:"country,omitempty"`
			Organization       []string `json:"organization,omitempty"`
			OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
			CommonName         string   `json:"commonName"`
		}{CommonName: "Test"},
		CertLifetime: "8760h",
	}

	err := ValidateTemplate(tmpl, nil, "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate type")
}

func TestContainsExtKeyUsage(t *testing.T) {
	assert.False(t, containsExtKeyUsage(nil, "CodeSigning"), "empty list (nil) should return false")
	assert.False(t, containsExtKeyUsage([]string{}, "CodeSigning"), "empty list should return false")
	assert.True(t, containsExtKeyUsage([]string{"CodeSigning"}, "CodeSigning"), "should find matching usage")
	assert.False(t, containsExtKeyUsage([]string{"OtherUsage"}, "CodeSigning"), "should not find non-matching usage")
}

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
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365),
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
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
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
				CertLifetime: "1y",
			},
			wantError: true,
		},
		{
			name: "valid_duration_based_template",
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
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
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
			name: "invalid_duration_format",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test"},
				CertLifetime: "1y",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := CreateCertificateFromTemplate(tt.tmpl, tt.parent)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
				if tt.tmpl.CertLifetime != "" {
					duration, _ := time.ParseDuration(tt.tmpl.CertLifetime)
					require.WithinDuration(t, time.Now().UTC(), cert.NotBefore, time.Second*5)
					require.WithinDuration(t, time.Now().UTC().Add(duration), cert.NotAfter, time.Second*5)
				}
			}
		})
	}
}

func TestSetCertificateUsages(t *testing.T) {
	cert := &x509.Certificate{}

	SetCertificateUsages(cert, []string{"certSign", "crlSign", "digitalSignature"}, nil)
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign to be set")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("expected KeyUsageCRLSign to be set")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature to be set")
	}

	newCert := &x509.Certificate{}
	SetCertificateUsages(newCert, nil, nil)
	if newCert.KeyUsage != x509.KeyUsage(0) {
		t.Error("expected no key usages to be set")
	}
	if len(newCert.ExtKeyUsage) != 0 {
		t.Error("expected no extended key usages to be set")
	}

	// Test extended key usages
	SetCertificateUsages(newCert, nil, []string{"CodeSigning"})
	if len(newCert.ExtKeyUsage) != 1 {
		t.Error("expected one extended key usage to be set")
	}
	if newCert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Error("expected CodeSigning extended key usage to be set")
	}
}

func TestValidateTemplateWithDurationAndTimestamps(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "valid_duration_based_template",
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
				CertLifetime: "8760h", // 1 year
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType: "root",
		},
		{
			name: "invalid_duration_format",
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
				CertLifetime: "1y", // invalid format
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType:  "root",
			wantError: "invalid certLife format",
		},
		{
			name: "negative_duration",
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
				CertLifetime: "-8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType:  "root",
			wantError: "certLife must be positive",
		},
		{
			name: "mixed_time_specifications",
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
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true},
			},
			certType: "root",
		},
		{
			name: "duration_based_leaf_with_parent",
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
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 2), // 2 years
			},
			certType: "leaf",
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

func TestValidateTemplateWithExtendedKeyUsage(t *testing.T) {
	tests := []struct {
		name      string
		template  *CertificateTemplate
		parent    *x509.Certificate
		certType  string
		wantError string
	}{
		{
			name: "valid_leaf_with_code_signing",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Leaf"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test CA"},
				CertLifetime: "24h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning", "TimeStamping"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false, MaxPathLen: 0},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(48 * time.Hour),
				IsCA:      true,
			},
			certType:  "leaf",
			wantError: "",
		},
		{
			name: "leaf_with_multiple_ext_key_usages",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Leaf"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test CA"},
				CertLifetime: "24h",
				KeyUsage:     []string{"digitalSignature"},
				ExtKeyUsage:  []string{"CodeSigning", "TimeStamping", "ServerAuth"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: false, MaxPathLen: 0},
			},
			parent: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "Test CA",
				},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(48 * time.Hour),
				IsCA:      true,
			},
			certType:  "leaf",
			wantError: "",
		},
		{
			name: "root_with_ext_key_usage",
			template: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test Root CA"},
				Issuer: struct {
					CommonName string `json:"commonName"`
				}{CommonName: "Test Root CA"},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign", "crlSign"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true, MaxPathLen: 1},
			},
			parent:    nil,
			certType:  "root",
			wantError: "root certificates should not have extended key usage",
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

func TestCreateCertificateFromTemplateWithExtendedFields(t *testing.T) {
	tests := []struct {
		name      string
		tmpl      *CertificateTemplate
		parent    *x509.Certificate
		wantError bool
		checkFunc func(*testing.T, *x509.Certificate)
	}{
		{
			name: "full_subject_fields",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{
					Country:            []string{"US", "CA"},
					Organization:       []string{"Test Org", "Another Org"},
					OrganizationalUnit: []string{"Unit 1", "Unit 2"},
					CommonName:         "Test Cert",
				},
				CertLifetime: "8760h",
				KeyUsage:     []string{"digitalSignature", "certSign"},
				ExtKeyUsage:  []string{"CodeSigning"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true, MaxPathLen: 1},
			},
			checkFunc: func(t *testing.T, cert *x509.Certificate) {
				assert.Equal(t, []string{"US", "CA"}, cert.Subject.Country)
				assert.Equal(t, []string{"Test Org", "Another Org"}, cert.Subject.Organization)
				assert.Equal(t, []string{"Unit 1", "Unit 2"}, cert.Subject.OrganizationalUnit)
				assert.Equal(t, "Test Cert", cert.Subject.CommonName)
				assert.True(t, cert.IsCA)
				assert.Equal(t, 1, cert.MaxPathLen)
				assert.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0)
				assert.True(t, cert.KeyUsage&x509.KeyUsageCertSign != 0)
				assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
			},
		},
		{
			name: "zero_max_path_len",
			tmpl: &CertificateTemplate{
				Subject: struct {
					Country            []string `json:"country,omitempty"`
					Organization       []string `json:"organization,omitempty"`
					OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
					CommonName         string   `json:"commonName"`
				}{CommonName: "Test CA"},
				CertLifetime: "8760h",
				KeyUsage:     []string{"certSign"},
				BasicConstraints: struct {
					IsCA       bool `json:"isCA"`
					MaxPathLen int  `json:"maxPathLen"`
				}{IsCA: true, MaxPathLen: 0},
			},
			checkFunc: func(t *testing.T, cert *x509.Certificate) {
				assert.True(t, cert.IsCA)
				assert.Equal(t, 0, cert.MaxPathLen)
				assert.True(t, cert.MaxPathLenZero)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := CreateCertificateFromTemplate(tt.tmpl, tt.parent)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
				if tt.checkFunc != nil {
					tt.checkFunc(t, cert)
				}
			}
		})
	}
}
