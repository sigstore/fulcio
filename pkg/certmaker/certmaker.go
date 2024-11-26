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
// It supports creating root and leaf certificates using (AWS, GCP, Azure).
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

// KMSConfig holds config for KMS providers.
type KMSConfig struct {
	Type      string            // KMS provider type: "awskms", "cloudkms", "azurekms"
	Region    string            // AWS region or Cloud location
	RootKeyID string            // Root CA key identifier
	LeafKeyID string            // Leaf CA key identifier
	Options   map[string]string // Provider-specific options
}

// InitKMS initializes KMS provider based on the given config, KMSConfig.
// Supports AWS KMS, Google Cloud KMS, and Azure Key Vault.
func InitKMS(ctx context.Context, config KMSConfig) (apiv1.KeyManager, error) {
	if err := ValidateKMSConfig(config); err != nil {
		return nil, fmt.Errorf("invalid KMS configuration: %w", err)
	}
	opts := apiv1.Options{
		Type: apiv1.Type(config.Type),
		URI:  "",
	}

	// Falls back to LeafKeyID if root is not set
	keyID := config.RootKeyID
	if keyID == "" {
		keyID = config.LeafKeyID
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
// It creates both root and leaf certificates using the provided templates
// and KMS signing keys.
func CreateCertificates(km apiv1.KeyManager, config KMSConfig, rootTemplatePath, leafTemplatePath, rootCertPath, leafCertPath string) error {
	// Parse root template
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

	// Create root cert
	rootCert, err := x509util.CreateCertificate(rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating root certificate: %w", err)
	}
	if err := WriteCertificateToFile(rootCert, rootCertPath); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	// Create leaf cert
	leafTmpl, err := ParseTemplate(leafTemplatePath, rootCert)
	if err != nil {
		return fmt.Errorf("error parsing leaf template: %w", err)
	}
	leafKeyName := config.LeafKeyID
	if config.Type == "azurekms" {
		leafKeyName = fmt.Sprintf("azurekms:vault=%s;name=%s",
			config.Options["vault-name"], config.LeafKeyID)
	}
	leafSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: leafKeyName,
	})
	if err != nil {
		return fmt.Errorf("error creating leaf signer: %w", err)
	}

	leafCert, err := x509util.CreateCertificate(leafTmpl, rootCert, leafSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating leaf certificate: %w", err)
	}

	if err := WriteCertificateToFile(leafCert, leafCertPath); err != nil {
		return fmt.Errorf("error writing leaf certificate: %w", err)
	}

	// Verify cert chain
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
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

	certType := "root"
	fmt.Printf("Your %s certificate has been saved in %s.\n", certType, filename)
	return nil
}

// ValidateKMSConfig ensures all required KMS configuration parameters are present
func ValidateKMSConfig(config KMSConfig) error {
	if config.Type == "" {
		return fmt.Errorf("KMS type cannot be empty")
	}
	if config.RootKeyID == "" && config.LeafKeyID == "" {
		return fmt.Errorf("at least one of RootKeyID or LeafKeyID must be specified")
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
		if config.LeafKeyID != "" && !strings.HasPrefix(config.LeafKeyID, "projects/") {
			return fmt.Errorf("cloudkms LeafKeyID must start with 'projects/'")
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
