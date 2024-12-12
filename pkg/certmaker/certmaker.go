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
// It supports creating root, intermediate, and leaf certs using (AWS, GCP, Azure).
package certmaker

import (
	"context"
	"crypto"
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
	Type              string
	Region            string
	RootKeyID         string
	IntermediateKeyID string
	LeafKeyID         string
	Options           map[string]string
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
	case "gcpkms":
		opts.Type = apiv1.Type("cloudkms")
		opts.URI = fmt.Sprintf("cloudkms:%s", keyID)
		if credFile, ok := config.Options["credentials-file"]; ok {
			if _, err := os.Stat(credFile); err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("credentials file not found: %s", credFile)
				}
				return nil, fmt.Errorf("error accessing credentials file: %w", err)
			}
			opts.URI += fmt.Sprintf("?credentials-file=%s", credFile)
		}
		km, err := cloudkms.New(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize GCP KMS: %w", err)
		}
		return km, nil
	case "azurekms":
		opts.URI = keyID
		if config.Options["tenant-id"] != "" {
			opts.URI += fmt.Sprintf("?tenant-id=%s", config.Options["tenant-id"])
		}
		return azurekms.New(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported KMS type: %s", config.Type)
	}
}

// CreateCertificates creates certificates using the provided KMS and templates.
// It creates 3 certificates (root -> intermediate -> leaf) if intermediateKeyID is provided,
// otherwise creates just 2 certs (root -> leaf).
func CreateCertificates(km apiv1.KeyManager, config KMSConfig,
	rootTemplatePath, leafTemplatePath string,
	rootCertPath, leafCertPath string,
	intermediateKeyID, intermediateTemplatePath, intermediateCertPath string) error {

	// Create root cert
	rootTmpl, err := ParseTemplate(rootTemplatePath, nil)
	if err != nil {
		return fmt.Errorf("error parsing root template: %w", err)
	}

	rootSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: config.RootKeyID,
	})
	if err != nil {
		return fmt.Errorf("error creating root signer: %w", err)
	}

	rootCert, err := x509util.CreateCertificate(rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		return fmt.Errorf("error creating root certificate: %w", err)
	}

	if err := WriteCertificateToFile(rootCert, rootCertPath); err != nil {
		return fmt.Errorf("error writing root certificate: %w", err)
	}

	var signingCert *x509.Certificate
	var signingKey crypto.Signer

	if intermediateKeyID != "" {
		// Create intermediate cert if key ID is provided
		intermediateTmpl, err := ParseTemplate(intermediateTemplatePath, rootCert)
		if err != nil {
			return fmt.Errorf("error parsing intermediate template: %w", err)
		}

		intermediateSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: intermediateKeyID,
		})
		if err != nil {
			return fmt.Errorf("error creating intermediate signer: %w", err)
		}

		intermediateCert, err := x509util.CreateCertificate(intermediateTmpl, rootCert, intermediateSigner.Public(), rootSigner)
		if err != nil {
			return fmt.Errorf("error creating intermediate certificate: %w", err)
		}

		if err := WriteCertificateToFile(intermediateCert, intermediateCertPath); err != nil {
			return fmt.Errorf("error writing intermediate certificate: %w", err)
		}

		signingCert = intermediateCert
		signingKey = intermediateSigner
	} else {
		signingCert = rootCert
		signingKey = rootSigner
	}

	// Create leaf cert
	leafTmpl, err := ParseTemplate(leafTemplatePath, signingCert)
	if err != nil {
		return fmt.Errorf("error parsing leaf template: %w", err)
	}

	leafSigner, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: config.LeafKeyID,
	})
	if err != nil {
		return fmt.Errorf("error creating leaf signer: %w", err)
	}

	leafCert, err := x509util.CreateCertificate(leafTmpl, signingCert, leafSigner.Public(), signingKey)
	if err != nil {
		return fmt.Errorf("error creating leaf certificate: %w", err)
	}

	if err := WriteCertificateToFile(leafCert, leafCertPath); err != nil {
		return fmt.Errorf("error writing leaf certificate: %w", err)
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

	// Determine cert type
	certType := "root"
	if !cert.IsCA {
		certType = "leaf"
	} else if cert.MaxPathLen == 0 {
		certType = "intermediate"
	}

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
		// AWS KMS validation
		if config.Region == "" {
			return fmt.Errorf("region is required for AWS KMS")
		}
		validateAWSKeyID := func(keyID, keyType string) error {
			if keyID == "" {
				return nil
			}
			if !strings.HasPrefix(keyID, "arn:aws:kms:") && !strings.HasPrefix(keyID, "alias/") {
				return fmt.Errorf("awskms %s must start with 'arn:aws:kms:' or 'alias/'", keyType)
			}
			return nil
		}
		if err := validateAWSKeyID(config.RootKeyID, "RootKeyID"); err != nil {
			return err
		}
		if err := validateAWSKeyID(config.IntermediateKeyID, "IntermediateKeyID"); err != nil {
			return err
		}
		if err := validateAWSKeyID(config.LeafKeyID, "LeafKeyID"); err != nil {
			return err
		}

	case "gcpkms":
		// GCP KMS validation
		validateGCPKeyID := func(keyID, keyType string) error {
			if keyID == "" {
				return nil
			}
			if !strings.HasPrefix(keyID, "projects/") {
				return fmt.Errorf("gcpkms %s must start with 'projects/'", keyType)
			}
			if !strings.Contains(keyID, "/locations/") || !strings.Contains(keyID, "/keyRings/") {
				return fmt.Errorf("invalid gcpkms key format for %s: %s", keyType, keyID)
			}
			return nil
		}
		if err := validateGCPKeyID(config.RootKeyID, "RootKeyID"); err != nil {
			return err
		}
		if err := validateGCPKeyID(config.IntermediateKeyID, "IntermediateKeyID"); err != nil {
			return err
		}
		if err := validateGCPKeyID(config.LeafKeyID, "LeafKeyID"); err != nil {
			return err
		}

	case "azurekms":
		// Azure KMS validation
		if config.Options == nil {
			return fmt.Errorf("options map is required for Azure KMS")
		}
		if config.Options["tenant-id"] == "" {
			return fmt.Errorf("tenant-id is required for Azure KMS")
		}
		validateAzureKeyID := func(keyID, keyType string) error {
			if keyID == "" {
				return nil
			}
			// Validate format: azurekms:name=<key-name>;vault=<vault-name>
			if !strings.HasPrefix(keyID, "azurekms:name=") {
				return fmt.Errorf("azurekms %s must start with 'azurekms:name='", keyType)
			}
			if !strings.Contains(keyID, ";vault=") {
				return fmt.Errorf("vault name is required for Azure Key Vault")
			}
			return nil
		}
		if err := validateAzureKeyID(config.RootKeyID, "RootKeyID"); err != nil {
			return err
		}
		if err := validateAzureKeyID(config.IntermediateKeyID, "IntermediateKeyID"); err != nil {
			return err
		}
		if err := validateAzureKeyID(config.LeafKeyID, "LeafKeyID"); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported KMS type: %s", config.Type)
	}

	return nil
}

// ValidateTemplatePath checks if the template file exists, has a .json extension,
// and contains valid JSON content.
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
