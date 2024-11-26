// Package certmaker provides template parsing and certificate generation functionality
// for creating Fulcio X.509 certificates from JSON templates. It supports both root and
// leaf certificate creation with configurable properties including key usage,
// extended key usage, and basic constraints.
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

// CertificateTemplate defines the JSON structure for Fulcio certificate templates.
// It supports both root and leaf CA certificates with code signing capabilities.
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

	if err := ValidateTemplate(&tmpl, parent); err != nil {
		return nil, err
	}

	return CreateCertificateFromTemplate(&tmpl, parent)
}

func ValidateTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) error {
	if tmpl.Subject.CommonName == "" {
		return fmt.Errorf("template subject.commonName cannot be empty")
	}

	if parent == nil && tmpl.Issuer.CommonName == "" {
		return fmt.Errorf("template issuer.commonName cannot be empty for root certificate")
	}

	if tmpl.BasicConstraints.IsCA && len(tmpl.KeyUsage) == 0 {
		return fmt.Errorf("CA certificate must specify at least one key usage")
	}

	if tmpl.BasicConstraints.IsCA {
		hasKeyUsageCertSign := false
		for _, usage := range tmpl.KeyUsage {
			if usage == "certSign" {
				hasKeyUsageCertSign = true
				break
			}
		}
		if !hasKeyUsageCertSign {
			return fmt.Errorf("CA certificate must have certSign key usage")
		}
	}

	// Fulcio-specific validation for code signing
	hasCodeSigning := false
	for _, usage := range tmpl.ExtKeyUsage {
		if usage == "CodeSigning" {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning && !tmpl.BasicConstraints.IsCA {
		return fmt.Errorf("Fulcio leaf certificates must have codeSign extended key usage")
	}

	return nil
}

func CreateCertificateFromTemplate(tmpl *CertificateTemplate, parent *x509.Certificate) (*x509.Certificate, error) {
	notBefore, err := time.Parse(time.RFC3339, tmpl.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid notBefore time format: %w", err)
	}

	notAfter, err := time.Parse(time.RFC3339, tmpl.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("invalid notAfter time format: %w", err)
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

func SetExtKeyUsages(cert *x509.Certificate, usages []string) {
	for _, usage := range usages {
		switch usage {
		case "CodeSigning":
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		}
	}
}
