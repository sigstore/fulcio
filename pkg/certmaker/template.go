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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/root-template.json
var rootTemplate string

//go:embed templates/intermediate-template.json
var intermediateTemplate string

//go:embed templates/leaf-template.json
var leafTemplate string

type TemplateSubject struct {
	Country            []string `json:"country"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizationalUnit"`
	CommonName         string   `json:"commonName"`
}

type TemplateBasicConstraints struct {
	IsCA       bool `json:"isCA"`
	MaxPathLen int  `json:"maxPathLen"`
}

type TemplateCert struct {
	Subject          TemplateSubject          `json:"subject"`
	KeyUsage         []string                 `json:"keyUsage"`
	ExtKeyUsage      []string                 `json:"extKeyUsage"`
	BasicConstraints TemplateBasicConstraints `json:"basicConstraints"`
}

func ParseTemplate(input any, parent *x509.Certificate, notAfter time.Time, publicKey crypto.PublicKey, commonName string) (*x509.Certificate, error) {
	var content string

	switch v := input.(type) {
	case string:
		content = v
	case []byte:
		content = string(v)
	default:
		return nil, fmt.Errorf("input must be either a template string or template content ([]byte)")
	}

	tmpl, err := template.New("cert").Parse(content)
	if err != nil {
		return nil, fmt.Errorf("error parsing template string: %w", err)
	}

	var buf bytes.Buffer
	type tmplData struct {
		Subject struct {
			CommonName string
		}
	}
	td := tmplData{}
	td.Subject.CommonName = commonName

	if err := tmpl.Execute(&buf, td); err != nil {
		return nil, fmt.Errorf("error executing template: %w", err)
	}

	var tc TemplateCert
	if err := json.Unmarshal(buf.Bytes(), &tc); err != nil {
		return nil, fmt.Errorf("error parsing template: error unmarshaling certificate: %w", err)
	}

	// Create base cert with public key
	x509Cert := &x509.Certificate{
		PublicKey:          publicKey,
		PublicKeyAlgorithm: determinePublicKeyAlgorithm(publicKey),
		NotBefore:          time.Now().UTC(),
		NotAfter:           notAfter,
		Subject: pkix.Name{
			CommonName:         tc.Subject.CommonName,
			Country:            tc.Subject.Country,
			Organization:       tc.Subject.Organization,
			OrganizationalUnit: tc.Subject.OrganizationalUnit,
		},
		IsCA:                  tc.BasicConstraints.IsCA,
		BasicConstraintsValid: true,
	}

	if x509Cert.IsCA {
		if tc.BasicConstraints.MaxPathLen == 0 {
			x509Cert.MaxPathLenZero = true
		} else {
			x509Cert.MaxPathLen = tc.BasicConstraints.MaxPathLen
		}
	}

	x509Cert.KeyUsage = parseKeyUsages(tc.KeyUsage)
	x509Cert.ExtKeyUsage = parseExtKeyUsages(tc.ExtKeyUsage)

	// Set parent cert info
	if parent != nil {
		x509Cert.Issuer = parent.Subject
		x509Cert.AuthorityKeyId = parent.SubjectKeyId
	}

	return x509Cert, nil
}

func parseKeyUsages(usages []string) x509.KeyUsage {
	var ku x509.KeyUsage
	for _, u := range usages {
		switch strings.ToLower(u) {
		case "digitalsignature":
			ku |= x509.KeyUsageDigitalSignature
		case "contentcommitment", "nonrepudiation":
			ku |= x509.KeyUsageContentCommitment
		case "keyencipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataencipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyagreement":
			ku |= x509.KeyUsageKeyAgreement
		case "certsign", "keycertsign":
			ku |= x509.KeyUsageCertSign
		case "crlsign":
			ku |= x509.KeyUsageCRLSign
		case "encipheronly":
			ku |= x509.KeyUsageEncipherOnly
		case "decipheronly":
			ku |= x509.KeyUsageDecipherOnly
		}
	}
	return ku
}

func parseExtKeyUsages(usages []string) []x509.ExtKeyUsage {
	var ekus []x509.ExtKeyUsage
	for _, u := range usages {
		switch strings.ToLower(u) {
		case "any":
			ekus = append(ekus, x509.ExtKeyUsageAny)
		case "serverauth":
			ekus = append(ekus, x509.ExtKeyUsageServerAuth)
		case "clientauth":
			ekus = append(ekus, x509.ExtKeyUsageClientAuth)
		case "codesigning":
			ekus = append(ekus, x509.ExtKeyUsageCodeSigning)
		case "emailprotection":
			ekus = append(ekus, x509.ExtKeyUsageEmailProtection)
		case "timestamping":
			ekus = append(ekus, x509.ExtKeyUsageTimeStamping)
		case "ocspsigning":
			ekus = append(ekus, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return ekus
}

func determinePublicKeyAlgorithm(publicKey crypto.PublicKey) x509.PublicKeyAlgorithm {
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case *rsa.PublicKey:
		return x509.RSA
	case ed25519.PublicKey:
		return x509.Ed25519
	default:
		return x509.ECDSA // Default to ECDSA if key type is unknown
	}
}

// Performs validation checks on the cert template
func ValidateTemplate(filename string, parent *x509.Certificate, commonName string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template not found at %s", filename)
		}
		return fmt.Errorf("error reading template file: %w", err)
	}

	_, err = ParseTemplate(content, parent, time.Now(), nil, commonName)
	if err != nil {
		return fmt.Errorf("invalid template JSON: %w", err)
	}

	return nil
}

// Returns a default JSON template string for the specified cert type
func GetDefaultTemplate(certType string) (string, error) {
	switch certType {
	case "root":
		if rootTemplate == "" {
			return "", fmt.Errorf("root template is required but not found")
		}
		return rootTemplate, nil
	// Both intermediate and leaf are optional - return empty if not found
	case "intermediate":
		if intermediateTemplate == "" {
			return "", nil
		}
		return intermediateTemplate, nil
	case "leaf":
		if leafTemplate == "" {
			return "", nil
		}
		return leafTemplate, nil
	default:
		return "", fmt.Errorf("invalid certificate type: %s", certType)
	}
}

// Ensures that required templates are present
func ValidateTemplateRequirements() error {
	if rootTemplate == "" {
		return fmt.Errorf("root template is required but not found")
	}
	return nil
}
