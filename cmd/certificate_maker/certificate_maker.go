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

// Package main implements a certificate creation utility for Fulcio.
// It supports creating root and intermediate certificates using(AWS, GCP, Azure).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/fulcio/pkg/certmaker"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	logger  *zap.Logger
	version string

	rootCmd = &cobra.Command{
		Use:     "fulcio-certificate-maker",
		Short:   "Create certificate chains for Fulcio CA",
		Long:    `A tool for creating root and intermediate certificates for Fulcio CA with code signing capabilities`,
		Version: version,
	}

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create certificate chain",
		RunE:  runCreate,
	}

	kmsType            string
	kmsRegion          string
	kmsKeyID           string
	kmsVaultName       string
	kmsTenantID        string
	kmsCredsFile       string
	rootTemplatePath   string
	intermTemplatePath string
	rootKeyID          string
	intermediateKeyID  string
	rootCertPath       string
	intermCertPath     string

	rawJSON = []byte(`{
		"level": "debug",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
		"initialFields": {"service": "sigstore-certificate-maker"},
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"levelEncoder": "lowercase",
			"timeKey": "timestamp",
			"timeEncoder": "iso8601"
		}
	}`)
)

func init() {
	logger = initLogger()

	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS provider type (awskms, cloudkms, azurekms)")
	createCmd.Flags().StringVar(&kmsRegion, "kms-region", "", "KMS region")
	createCmd.Flags().StringVar(&kmsKeyID, "kms-key-id", "", "KMS key identifier")
	createCmd.Flags().StringVar(&kmsVaultName, "kms-vault-name", "", "Azure KMS vault name")
	createCmd.Flags().StringVar(&kmsTenantID, "kms-tenant-id", "", "Azure KMS tenant ID")
	createCmd.Flags().StringVar(&kmsCredsFile, "kms-credentials-file", "", "Path to credentials file (for Google Cloud KMS)")
	createCmd.Flags().StringVar(&rootTemplatePath, "root-template", "pkg/certmaker/templates/root-template.json", "Path to root certificate template")
	createCmd.Flags().StringVar(&intermTemplatePath, "intermediate-template", "pkg/certmaker/templates/intermediate-template.json", "Path to intermediate certificate template")
	createCmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "KMS key identifier for root certificate")
	createCmd.Flags().StringVar(&intermediateKeyID, "intermediate-key-id", "", "KMS key identifier for intermediate certificate")
	createCmd.Flags().StringVar(&rootCertPath, "root-cert", "root.pem", "Output path for root certificate")
	createCmd.Flags().StringVar(&intermCertPath, "intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Build KMS config from flags and environment
	config := certmaker.KMSConfig{
		Type:              getConfigValue(kmsType, "KMS_TYPE"),
		Region:            getConfigValue(kmsRegion, "KMS_REGION"),
		RootKeyID:         getConfigValue(rootKeyID, "KMS_ROOT_KEY_ID"),
		IntermediateKeyID: getConfigValue(intermediateKeyID, "KMS_INTERMEDIATE_KEY_ID"),
		Options:           make(map[string]string),
	}

	// Handle KMS provider options
	switch config.Type {
	case "cloudkms":
		if credsFile := getConfigValue(kmsCredsFile, "KMS_CREDENTIALS_FILE"); credsFile != "" {
			config.Options["credentials-file"] = credsFile
		}
	case "azurekms":
		if vaultName := getConfigValue(kmsVaultName, "KMS_VAULT_NAME"); vaultName != "" {
			config.Options["vault-name"] = vaultName
		}
		if tenantID := getConfigValue(kmsTenantID, "KMS_TENANT_ID"); tenantID != "" {
			config.Options["tenant-id"] = tenantID
		}
	}

	ctx := context.Background()
	km, err := certmaker.InitKMS(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Validate template paths
	if err := certmaker.ValidateTemplatePath(rootTemplatePath); err != nil {
		return fmt.Errorf("root template error: %w", err)
	}
	if err := certmaker.ValidateTemplatePath(intermTemplatePath); err != nil {
		return fmt.Errorf("intermediate template error: %w", err)
	}

	return certmaker.CreateCertificates(km, config, rootTemplatePath, intermTemplatePath, rootCertPath, intermCertPath)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("Command failed", zap.Error(err))
	}
}

func getConfigValue(flagValue, envVar string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envVar)
}

func initLogger() *zap.Logger {
	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	return zap.Must(cfg.Build())
}
