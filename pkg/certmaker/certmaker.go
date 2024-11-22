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

// Package certmaker implements a certificate creation utility for Fulcio.
// It supports creating root and intermediate certificates using (AWS, GCP, Azure).
package certmaker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/awskms"
	"go.step.sm/crypto/kms/azurekms"
	"go.step.sm/crypto/kms/cloudkms"
	"go.step.sm/crypto/x509util"
)

type KMSConfig struct {
	Type              string            // KMS provider type: "awskms", "cloudkms", "azurekms"
	Region            string            // AWS region or Cloud location
	RootKeyID         string            // Root CA key identifier
	IntermediateKeyID string            // Intermediate CA key identifier
	Options           map[string]string // Provider-specific options
}

func InitKMS(ctx context.Context, config KMSConfig) (apiv1.KeyManager, error) {
	if err := ValidateKMSConfig(config); err != nil {
		return nil, fmt.Errorf("invalid KMS configuration: %w", err)
	}

	opts := apiv1.Options{
		Type: apiv1.Type(config.Type),
		URI:  "",
	}

	// Use RootKeyID as the primary key ID, fall back to IntermediateKeyID if root is not set
	keyID := config.RootKeyID
	if keyID == "" {
		keyID = config.IntermediateKeyID
	}

	switch config.Type {
	case "awskms":
		opts.URI = fmt.Sprintf("awskms:///%s?region=%s", keyID, config.Region)
		return awskms.New(ctx, opts)
	case "cloudkms":
		opts.URI = fmt.Sprintf("cloudkms:%s", keyID)
		if credFile, ok := config.Options["credentials-file"]; ok {
			opts.URI += fmt.Sprintf("?credentials-file=%s", credFile)
		}
		return cloudkms.New(ctx, opts)
	case "azurekms":
		opts.URI = fmt.Sprintf("azurekms://%s.vault.azure.net/keys/%s",
			config.Options["vault-name"], keyID)
		if config.Options["tenant-id"] != "" {
			opts.URI += fmt.Sprintf("?tenant-id=%s", config.Options["tenant-id"])
		}
		return azurekms.New(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported KMS type: %s", config.Type)
	}
}

// CreateCertificates generates a certificate chain using the configured KMS provider.
// It creates both root and intermediate certificates using the provided templates
// and KMS signing keys.
func CreateCertificates(km apiv1.KeyManager, config KMSConfig, rootTemplatePath, intermediateTemplatePath, rootCertPath, intermCertPath string) error {
	// Parse templates
	rootTmpl, err := ParseTemplate(rootTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing root template: %w", err)
	}

	rootKeyName := config.RootKeyID
	if config.Type == "azurekms" {
		rootKeyName = fmt.Sprintf("azurekms:vault=%s;name=%s",
			config.Options["vault-name"], config.RootKeyID)
	}

	rootSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: rootKeyName,
	})
	if err != nil {
		return fmt.Errorf("error creating root signer: %w", err)
	}

	// Create root certificate
	rootCert, err := x509util.CreateCertificate(rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating root certificate: %w", err)
	}

	// Parse intermediate template
	intermediateTmpl, err := ParseTemplate(intermediateTemplatePath, rootCert)
	if err != nil {
		return fmt.Errorf("error parsing intermediate template: %w", err)
	}

	intermediateKeyName := config.IntermediateKeyID
	if config.Type == "azurekms" {
		intermediateKeyName = fmt.Sprintf("azurekms:vault=%s;name=%s",
			config.Options["vault-name"], config.IntermediateKeyID)
	}

	intermediateSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: intermediateKeyName,
	})
	if err != nil {
		return fmt.Errorf("error creating intermediate signer: %w", err)
	}

	// Create intermediate certificate
	intermediateCert, err := x509util.CreateCertificate(intermediateTmpl, rootCert, intermediateSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating intermediate certificate: %w", err)
	}

	if err := WriteCertificateToFile(rootCert, rootCertPath); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	if err := WriteCertificateToFile(intermediateCert, intermCertPath); err != nil {
		return fmt.Errorf("error writing intermediate certificate: %w", err)
	}

	// Verify certificate chain
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	if _, err := intermediateCert.Verify(x509.VerifyOptions{
		Roots: pool,
	}); err != nil {
		return fmt.Errorf("CA.Intermediate.Verify() error = %v", err)
	}

	return nil
}

// WriteCertificateToFile writes an X.509 certificate to a PEM-encoded file
func WriteCertificateToFile(cert *x509.Certificate, filename string) error {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	if err := pem.Encode(file, certPEM); err != nil {
		return fmt.Errorf("failed to write certificate to file %s: %w", filename, err)
	}

	return nil
}

// ValidateKMSConfig ensures all required KMS configuration parameters are present
func ValidateKMSConfig(config KMSConfig) error {
	if config.Type == "" {
		return fmt.Errorf("KMS type cannot be empty")
	}
	if config.RootKeyID == "" && config.IntermediateKeyID == "" {
		return fmt.Errorf("at least one of RootKeyID or IntermediateKeyID must be specified")
	}

	switch config.Type {
	case "awskms":
		if config.Region == "" {
			return fmt.Errorf("region is required for AWS KMS")
		}
	case "cloudkms":
		if config.RootKeyID != "" && !strings.HasPrefix(config.RootKeyID, "projects/") {
			return fmt.Errorf("cloudkms RootKeyID must start with 'projects/'")
		}
		if config.IntermediateKeyID != "" && !strings.HasPrefix(config.IntermediateKeyID, "projects/") {
			return fmt.Errorf("cloudkms IntermediateKeyID must start with 'projects/'")
		}
	case "azurekms":
		if config.Options["vault-name"] == "" {
			return fmt.Errorf("vault-name is required for Azure KMS")
		}
		if config.Options["tenant-id"] == "" {
			return fmt.Errorf("tenant-id is required for Azure KMS")
		}
	}

	return nil
}

// ValidateTemplatePath validates that a template file exists and contains valid JSON
func ValidateTemplatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("template not found at %s: %w", path, err)
	}

	if !strings.HasSuffix(path, ".json") {
		return fmt.Errorf("template file must have .json extension: %s", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading template file: %w", err)
	}

	var js json.RawMessage
	if err := json.Unmarshal(content, &js); err != nil {
		return fmt.Errorf("invalid JSON in template file: %w", err)
	}

	return nil
}
