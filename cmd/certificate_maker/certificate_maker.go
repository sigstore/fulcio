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
// It supports creating root and leaf certificates using (AWS, GCP, Azure).
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/fulcio/pkg/certmaker"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// CLI flags and env vars for config.
// Supports AWS KMS, Google Cloud KMS, and Azure Key Vault configurations.
var (
	version string

	rootCmd = &cobra.Command{
		Use:     "fulcio-certificate-maker",
		Short:   "Create certificate chains for Fulcio",
		Long:    `A tool for creating root, intermediate, and leaf certificates for Fulcio with code signing capabilities`,
		Version: version,
	}

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create certificate chain",
		RunE:  runCreate,
	}

	kmsType              string
	kmsRegion            string
	kmsKeyID             string
	kmsTenantID          string
	kmsCredsFile         string
	rootTemplatePath     string
	leafTemplatePath     string
	rootKeyID            string
	leafKeyID            string
	rootCertPath         string
	leafCertPath         string
	intermediateKeyID    string
	intermediateTemplate string
	intermediateCert     string
	kmsVaultToken        string
	kmsVaultAddr         string
)

func mustBindPFlag(key string, flag *pflag.Flag) {
	if err := viper.BindPFlag(key, flag); err != nil {
		log.Logger.Fatal("failed to bind flag", zap.String("flag", key), zap.Error(err))
	}
}

func mustBindEnv(key, envVar string) {
	if err := viper.BindEnv(key, envVar); err != nil {
		log.Logger.Fatal("failed to bind env var", zap.String("var", envVar), zap.Error(err))
	}
}

func init() {
	log.ConfigureLogger("prod")

	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS provider type (awskms, gcpkms, azurekms, hashivault)")
	createCmd.Flags().StringVar(&kmsRegion, "aws-region", "", "AWS KMS region")
	createCmd.Flags().StringVar(&kmsKeyID, "kms-key-id", "", "KMS key identifier")
	createCmd.Flags().StringVar(&kmsTenantID, "azure-tenant-id", "", "Azure KMS tenant ID")
	createCmd.Flags().StringVar(&kmsCredsFile, "gcp-credentials-file", "", "Path to credentials file for GCP KMS")
	createCmd.Flags().StringVar(&rootTemplatePath, "root-template", "pkg/certmaker/templates/root-template.json", "Path to root certificate template")
	createCmd.Flags().StringVar(&leafTemplatePath, "leaf-template", "pkg/certmaker/templates/leaf-template.json", "Path to leaf certificate template")
	createCmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "KMS key identifier for root certificate")
	createCmd.Flags().StringVar(&leafKeyID, "leaf-key-id", "", "KMS key identifier for leaf certificate")
	createCmd.Flags().StringVar(&rootCertPath, "root-cert", "root.pem", "Output path for root certificate")
	createCmd.Flags().StringVar(&leafCertPath, "leaf-cert", "leaf.pem", "Output path for leaf certificate")
	createCmd.Flags().StringVar(&intermediateKeyID, "intermediate-key-id", "", "KMS key identifier for intermediate certificate")
	createCmd.Flags().StringVar(&intermediateTemplate, "intermediate-template", "pkg/certmaker/templates/intermediate-template.json", "Path to intermediate certificate template")
	createCmd.Flags().StringVar(&intermediateCert, "intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")
	createCmd.Flags().StringVar(&kmsVaultToken, "vault-token", "", "HashiVault token")
	createCmd.Flags().StringVar(&kmsVaultAddr, "vault-address", "", "HashiVault server address")

	mustBindPFlag("kms-type", createCmd.Flags().Lookup("kms-type"))
	mustBindPFlag("aws-region", createCmd.Flags().Lookup("aws-region"))
	mustBindPFlag("kms-key-id", createCmd.Flags().Lookup("kms-key-id"))
	mustBindPFlag("azure-tenant-id", createCmd.Flags().Lookup("azure-tenant-id"))
	mustBindPFlag("gcp-credentials-file", createCmd.Flags().Lookup("gcp-credentials-file"))
	mustBindPFlag("root-template", createCmd.Flags().Lookup("root-template"))
	mustBindPFlag("leaf-template", createCmd.Flags().Lookup("leaf-template"))
	mustBindPFlag("root-key-id", createCmd.Flags().Lookup("root-key-id"))
	mustBindPFlag("leaf-key-id", createCmd.Flags().Lookup("leaf-key-id"))
	mustBindPFlag("root-cert", createCmd.Flags().Lookup("root-cert"))
	mustBindPFlag("leaf-cert", createCmd.Flags().Lookup("leaf-cert"))
	mustBindPFlag("intermediate-key-id", createCmd.Flags().Lookup("intermediate-key-id"))
	mustBindPFlag("intermediate-template", createCmd.Flags().Lookup("intermediate-template"))
	mustBindPFlag("intermediate-cert", createCmd.Flags().Lookup("intermediate-cert"))
	mustBindPFlag("vault-token", createCmd.Flags().Lookup("vault-token"))
	mustBindPFlag("vault-address", createCmd.Flags().Lookup("vault-address"))

	mustBindEnv("kms-type", "KMS_TYPE")
	mustBindEnv("aws-region", "AWS_REGION")
	mustBindEnv("kms-key-id", "KMS_KEY_ID")
	mustBindEnv("azure-tenant-id", "AZURE_TENANT_ID")
	mustBindEnv("gcp-credentials-file", "GCP_CREDENTIALS_FILE")
	mustBindEnv("root-key-id", "KMS_ROOT_KEY_ID")
	mustBindEnv("leaf-key-id", "KMS_LEAF_KEY_ID")
	mustBindEnv("intermediate-key-id", "KMS_INTERMEDIATE_KEY_ID")
	mustBindEnv("vault-token", "VAULT_TOKEN")
	mustBindEnv("vault-address", "VAULT_ADDR")
}

func runCreate(_ *cobra.Command, _ []string) error {
	defer func() { rootCmd.SilenceUsage = true }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build KMS config from flags and environment
	config := certmaker.KMSConfig{
		Type:              viper.GetString("kms-type"),
		Region:            viper.GetString("aws-region"),
		RootKeyID:         viper.GetString("root-key-id"),
		IntermediateKeyID: viper.GetString("intermediate-key-id"),
		LeafKeyID:         viper.GetString("leaf-key-id"),
		Options:           make(map[string]string),
	}

	// Handle KMS provider options
	switch config.Type {
	case "gcpkms":
		if credsFile := viper.GetString("gcp-credentials-file"); credsFile != "" {
			// Check if credentials file exists before trying to use it
			if _, err := os.Stat(credsFile); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("failed to initialize KMS: credentials file not found: %s", credsFile)
				}
				return fmt.Errorf("failed to initialize KMS: error accessing credentials file: %w", err)
			}
			config.Options["credentials-file"] = credsFile
		}
	case "azurekms":
		if tenantID := viper.GetString("azure-tenant-id"); tenantID != "" {
			config.Options["tenant-id"] = tenantID
		}
	case "hashivault":
		if token := viper.GetString("vault-token"); token != "" {
			config.Options["token"] = token
		}
		if addr := viper.GetString("vault-address"); addr != "" {
			config.Options["address"] = addr
		}
	}

	km, err := certmaker.InitKMS(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Validate template paths
	if err := certmaker.ValidateTemplatePath(rootTemplatePath); err != nil {
		return fmt.Errorf("root template error: %w", err)
	}
	if err := certmaker.ValidateTemplatePath(leafTemplatePath); err != nil {
		return fmt.Errorf("leaf template error: %w", err)
	}

	return certmaker.CreateCertificates(km, config, rootTemplatePath, leafTemplatePath, rootCertPath, leafCertPath, intermediateKeyID, intermediateTemplate, intermediateCert)
}

func main() {
	rootCmd.SilenceErrors = true
	if err := rootCmd.Execute(); err != nil {
		if rootCmd.SilenceUsage {
			log.Logger.Fatal("Command failed", zap.Error(err))
		} else {
			os.Exit(1)
		}
	}
}
