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
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"fmt"
	"os"
	"time"

	"go.step.sm/crypto/x509util"
)

//go:embed templates/root-template.json
var rootTemplate string

//go:embed templates/intermediate-template.json
var intermediateTemplate string

//go:embed templates/leaf-template.json
var leafTemplate string

func ParseTemplate(input interface{}, parent *x509.Certificate, notAfter time.Time, publicKey crypto.PublicKey, commonName string) (*x509.Certificate, error) {
	var content string

	switch v := input.(type) {
	case string:
		content = v
	case []byte:
		content = string(v)
	default:
		return nil, fmt.Errorf("input must be either a template string or template content ([]byte)")
	}

	// Get cert life and subject from template
	data := x509util.NewTemplateData()
	if commonName != "" {
		fmt.Printf("Using CN from CLI: %s\n", commonName)
		data.SetSubject(x509util.Subject{CommonName: commonName})
	} else {
		// Get CN from template
		cert, err := x509util.NewCertificateFromX509(&x509.Certificate{}, x509util.WithTemplate(content, data))
		if err == nil && cert != nil {
			fmt.Printf("Using CN from template: %s\n", cert.Subject.CommonName)
			data.SetSubject(x509util.Subject{CommonName: cert.Subject.CommonName})
		} else {
			fmt.Printf("Using CN from template: <none>\n")
		}
	}

	// Create base cert with public key
	baseCert := &x509.Certificate{
		PublicKey:          publicKey,
		PublicKeyAlgorithm: determinePublicKeyAlgorithm(publicKey),
		NotBefore:          time.Now().UTC(),
		NotAfter:           notAfter,
	}

	cert, err := x509util.NewCertificateFromX509(baseCert, x509util.WithTemplate(content, data))
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}

	x509Cert := cert.GetCertificate()

	// Set parent cert info
	if parent != nil {
		x509Cert.Issuer = parent.Subject
		x509Cert.AuthorityKeyId = parent.SubjectKeyId
	}

	// Ensure cert life is set
	x509Cert.NotBefore = baseCert.NotBefore
	x509Cert.NotAfter = baseCert.NotAfter

	return x509Cert, nil
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
func ValidateTemplate(filename string, _ *x509.Certificate, _ string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template not found at %s", filename)
		}
		return fmt.Errorf("error reading template file: %w", err)
	}

	// Parse template via x509util to avoid issues with templating
	data := x509util.NewTemplateData()
	baseCert := &x509.Certificate{}
	_, err = x509util.NewCertificateFromX509(baseCert, x509util.WithTemplate(string(content), data))
	if err != nil {
		return fmt.Errorf("invalid template JSON: %w", err)
	}

	return nil
}

// Returns a default JSON template string for the specified cert type
func GetDefaultTemplate(certType string) (string, error) {
	switch certType {
	case "root":
		return rootTemplate, nil
	case "intermediate":
		return intermediateTemplate, nil
	case "leaf":
		return leafTemplate, nil
	default:
		return "", fmt.Errorf("invalid certificate type: %s", certType)
	}
}
