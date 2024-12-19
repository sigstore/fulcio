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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CertificateTemplate defines the structure for the JSON certificate templates
type CertificateTemplate struct {
	Subject struct {
		Country            []string `json:"country,omitempty"`
		Organization       []string `json:"organization,omitempty"`
		OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
		CommonName         string   `json:"commonName"`
	} `json:"subject"`
	Issuer struct {
		CommonName string `json:"commonName"`
	} `json:"issuer"`
	NotBefore        string   `json:"notBefore"`
	NotAfter         string   `json:"notAfter"`
	KeyUsage         []string `json:"keyUsage"`
	BasicConstraints struct {
		IsCA       bool `json:"isCA"`
		MaxPathLen int  `json:"maxPathLen"`
	} `json:"basicConstraints"`
	Extensions []struct {
		ID       string `json:"id"`
		Critical bool   `json:"critical"`
		Value    string `json:"value"`
	} `json:"extensions,omitempty"`
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`
}

// ParseTemplate creates an x509 certificate from JSON template
func ParseTemplate(filename string, parent *x509.Certificate) (*x509.Certificate, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading template file: %w", err)
	}

	var tmpl CertificateTemplate
	if err := json.Unmarshal(content, &tmpl); err != nil {
		return nil, fmt.Errorf("error parsing template JSON: %w", err)
	}

	certType := "root"
	if parent != nil {
		if tmpl.BasicConstraints.IsCA {
			certType = "intermediate"
		} else {
			certType = "leaf"
		}
	}

	if err := ValidateTemplate(&tmpl, parent, certType); err != nil {
		return nil, err
	}

	return CreateCertificateFromTemplate(&tmpl, parent)
}

// ValidateTemplate performs validation checks on the certificate template.
func ValidateTemplate(tmpl *CertificateTemplate, parent *x509.Certificate, certType string) error {
	if tmpl.NotBefore == "" || tmpl.NotAfter == "" {
		return fmt.Errorf("notBefore and notAfter times must be specified")
	}

	notBefore, err := time.Parse(time.RFC3339, tmpl.NotBefore)
	if err != nil {
		return fmt.Errorf("invalid notBefore time format: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, tmpl.NotAfter)
	if err != nil {
		return fmt.Errorf("invalid notAfter time format: %w", err)
	}
	if notBefore.After(notAfter) {
		return fmt.Errorf("NotBefore time must be before NotAfter time")
	}

	if tmpl.Subject.CommonName == "" {
		return fmt.Errorf("template subject.commonName cannot be empty")
	}

	switch certType {
	case "root":
		if !tmpl.BasicConstraints.IsCA {
			return fmt.Errorf("root certificate must be a CA")
		}
		if tmpl.Issuer.CommonName == "" {
			return fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
		}
	case "intermediate":
		if parent == nil {
			return fmt.Errorf("parent certificate is required for non-root certificates")
		}
		if !tmpl.BasicConstraints.IsCA {
			return fmt.Errorf("intermediate certificate must be a CA")
		}
		if tmpl.BasicConstraints.MaxPathLen != 0 {
			return fmt.Errorf("intermediate CA MaxPathLen must be 0")
		}
		if !containsKeyUsage(tmpl.KeyUsage, "certSign") {
			return fmt.Errorf("intermediate CA certificate must have certSign key usage")
		}
	case "leaf":
		if parent == nil {
			return fmt.Errorf("parent certificate is required for non-root certificates")
		}
		if tmpl.BasicConstraints.IsCA {
			return fmt.Errorf("leaf certificate cannot be a CA")
		}
		if containsKeyUsage(tmpl.KeyUsage, "certSign") {
			return fmt.Errorf("leaf certificate cannot have certSign key usage")
		}
		hasCodeSigning := false
		for _, usage := range tmpl.ExtKeyUsage {
			if usage == "CodeSigning" {
				hasCodeSigning = true
				break
			}
		}
		if !hasCodeSigning {
			return fmt.Errorf("Fulcio leaf certificates must have codeSign extended key usage")
		}
	default:
		return fmt.Errorf("invalid certificate type: %s", certType)
	}

	// Basic CA validation
	if tmpl.BasicConstraints.IsCA {
		if len(tmpl.KeyUsage) == 0 {
			return fmt.Errorf("CA certificate must specify at least one key usage")
		}
		if !containsKeyUsage(tmpl.KeyUsage, "certSign") {
			return fmt.Errorf("CA certificate must have certSign key usage")
		}
	}

	// Time validation against parent
	if parent != nil {
		if notBefore.Before(parent.NotBefore) {
			return fmt.Errorf("certificate notBefore time cannot be before parent's notBefore time")
		}
		if notAfter.After(parent.NotAfter) {
			return fmt.Errorf("certificate notAfter time cannot be after parent's notAfter time")
		}
	}

	return nil
}

// CreateCertificateFromTemplate creates an x509.Certificate from the provided template
func CreateCertificateFromTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) (*x509.Certificate, error) {
	notBefore, err := time.Parse(time.RFC3339, tmpl.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid notBefore time format: %w", err)
	}

	notAfter, err := time.Parse(time.RFC3339, tmpl.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("invalid notAfter time format: %w", err)
	}

	if notBefore.After(notAfter) {
		return nil, fmt.Errorf("NotBefore time must be before NotAfter time")
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			Country:            tmpl.Subject.Country,
			Organization:       tmpl.Subject.Organization,
			OrganizationalUnit: tmpl.Subject.OrganizationalUnit,
			CommonName:         tmpl.Subject.CommonName,
		},
		Issuer: func() pkix.Name {
			if parent != nil {
				return parent.Subject
			}
			return pkix.Name{CommonName: tmpl.Issuer.CommonName}
		}(),
		SerialNumber:          big.NewInt(time.Now().Unix()),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  tmpl.BasicConstraints.IsCA,
	}

	if tmpl.BasicConstraints.IsCA {
		cert.MaxPathLen = tmpl.BasicConstraints.MaxPathLen
		cert.MaxPathLenZero = tmpl.BasicConstraints.MaxPathLen == 0
	}

	SetKeyUsages(cert, tmpl.KeyUsage)
	SetExtKeyUsages(cert, tmpl.ExtKeyUsage)

	return cert, nil
}

// SetKeyUsages applies the specified key usage to cert(s)
// supporting certSign, crlSign, and digitalSignature usages.
func SetKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		switch usage {
		case "certSign":
			cert.KeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			cert.KeyUsage |= x509.KeyUsageCRLSign
		case "digitalSignature":
			cert.KeyUsage |= x509.KeyUsageDigitalSignature
		}
	}
}

// SetExtKeyUsages applies the specified extended key usage flags to the cert(s).
// Currently only supports CodeSigning usage.
func SetExtKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		if usage == "CodeSigning" {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		}
	}
}

// Helper function to check if a key usage is present
func containsKeyUsage(usages []string, target string) bool {
	for _, usage := range usages {
		if usage == target {
			return true
		}
	}
	return false
}
