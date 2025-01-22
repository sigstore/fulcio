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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConfigValue(t *testing.T) {
	var (
		kmsType          string
		awsKMSRegion     string
		azureKMSTenantID string
		gcpKMSCredsFile  string
		hashiVaultToken  string
		hashiVaultAddr   string

		rootKeyID        string
		rootTemplatePath string
		rootCertPath     string

		intermediateKeyID        string
		intermediateTemplatePath string
		intermediateCertPath     string

		leafKeyID        string
		leafTemplatePath string
		leafCertPath     string
	)

	cmd := &cobra.Command{
		Run: func(_ *cobra.Command, _ []string) {
		},
	}

	cmd.Flags().StringVar(&kmsType, "kms-type", "", "KMS provider type")
	cmd.Flags().StringVar(&awsKMSRegion, "aws-region", "", "AWS KMS region")
	cmd.Flags().StringVar(&azureKMSTenantID, "azure-tenant-id", "", "Azure KMS tenant ID")
	cmd.Flags().StringVar(&gcpKMSCredsFile, "gcp-credentials-file", "", "Path to credentials file for GCP KMS")
	cmd.Flags().StringVar(&hashiVaultToken, "vault-token", "", "HashiVault token")
	cmd.Flags().StringVar(&hashiVaultAddr, "vault-address", "", "HashiVault server address")

	cmd.Flags().StringVar(&rootKeyID, "root-key-id", "", "KMS key identifier for root certificate")
	cmd.Flags().StringVar(&rootTemplatePath, "root-template", "", "Path to root certificate template")
	cmd.Flags().StringVar(&rootCertPath, "root-cert", "root.pem", "Output path for root certificate")

	cmd.Flags().StringVar(&intermediateKeyID, "intermediate-key-id", "", "KMS key identifier for intermediate certificate")
	cmd.Flags().StringVar(&intermediateTemplatePath, "intermediate-template", "", "Path to intermediate certificate template")
	cmd.Flags().StringVar(&intermediateCertPath, "intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")

	cmd.Flags().StringVar(&leafKeyID, "leaf-key-id", "", "KMS key identifier for leaf certificate")
	cmd.Flags().StringVar(&leafTemplatePath, "leaf-template", "", "Path to leaf certificate template")
	cmd.Flags().StringVar(&leafCertPath, "leaf-cert", "leaf.pem", "Output path for leaf certificate")

	viper.Reset()
	viper.BindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
	viper.BindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
	viper.BindPFlag("azure-tenant-id", cmd.Flags().Lookup("azure-tenant-id"))
	viper.BindPFlag("gcp-credentials-file", cmd.Flags().Lookup("gcp-credentials-file"))
	viper.BindPFlag("vault-token", cmd.Flags().Lookup("vault-token"))
	viper.BindPFlag("vault-address", cmd.Flags().Lookup("vault-address"))
	viper.BindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
	viper.BindPFlag("intermediate-key-id", cmd.Flags().Lookup("intermediate-key-id"))
	viper.BindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))

	type testCase struct {
		name      string
		args      []string
		wantValue string
		flag      string
	}

	tests := []testCase{
		{
			name:      "get KMS type from flag",
			args:      []string{"--kms-type", "awskms"},
			flag:      "kms-type",
			wantValue: "awskms",
		},
		{
			name:      "get AWS region from flag",
			args:      []string{"--aws-region", "us-west-2"},
			flag:      "aws-region",
			wantValue: "us-west-2",
		},
		{
			name:      "get Azure tenant ID from flag",
			args:      []string{"--azure-tenant-id", "tenant-123"},
			flag:      "azure-tenant-id",
			wantValue: "tenant-123",
		},
		{
			name:      "get GCP credentials file from flag",
			args:      []string{"--gcp-credentials-file", "/path/to/creds.json"},
			flag:      "gcp-credentials-file",
			wantValue: "/path/to/creds.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			require.NoError(t, err)
			got := viper.GetString(tt.flag)
			assert.Equal(t, tt.wantValue, got)
		})
	}
}

func TestInitLogger(t *testing.T) {
	log.ConfigureLogger("prod")
	require.NotNil(t, log.Logger)
}

func TestRunCreate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	rootTemplate := `{
		"subject": {
			"commonName": "Test Root CA"
		},
		"issuer": {
			"commonName": "Test Root CA"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		},
		"certLife": "8760h"
	}`

	leafTemplate := `{
		"subject": {
			"commonName": "Test Leaf"
		},
		"notBefore": "2024-01-01T00:00:00Z",
		"notAfter": "2025-01-01T00:00:00Z",
		"keyUsage": ["digitalSignature"],
		"extKeyUsage": ["CodeSigning"],
		"basicConstraints": {
			"isCA": false
		},
		"certLife": "8760h"
	}`

	rootTmplPath := filepath.Join(tmpDir, "root-template.json")
	leafTmplPath := filepath.Join(tmpDir, "leaf-template.json")
	err = os.WriteFile(rootTmplPath, []byte(rootTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(leafTmplPath, []byte(leafTemplate), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		args      []string
		envVars   map[string]string
		wantError bool
		errMsg    string
	}{
		{
			name: "missing KMS type",
			args: []string{
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "KMS type cannot be empty",
		},
		{
			name: "invalid KMS type",
			args: []string{
				"--kms-type", "invalid",
				"--aws-region", "us-west-2",
				"--root-key-id", "test-root-key",
				"--leaf-key-id", "test-leaf-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "unsupported KMS type",
		},
		{
			name: "missing root template",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", "nonexistent.json",
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "template not found at nonexistent.json",
		},
		{
			name: "missing leaf template",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", "nonexistent.json",
			},
			wantError: true,
			errMsg:    "template not found at nonexistent.json",
		},
		{
			name: "GCP KMS with credentials file",
			args: []string{
				"--kms-type", "gcpkms",
				"--root-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				"--leaf-key-id", "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/leaf-key/cryptoKeyVersions/1",
				"--gcp-credentials-file", "/nonexistent/credentials.json",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "failed to initialize KMS: credentials file not found",
		},
		{
			name: "Azure KMS without tenant ID",
			args: []string{
				"--kms-type", "azurekms",
				"--root-key-id", "azurekms:name=test-key;vault=test-vault",
				"--leaf-key-id", "azurekms:name=leaf-key;vault=test-vault",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "tenant-id is required for Azure KMS",
		},
		{
			name: "AWS KMS test",
			args: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-key",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "error getting root public key: getting public key: operation error KMS: GetPublicKey",
		},
		{
			name: "HashiVault KMS without token",
			args: []string{
				"--kms-type", "hashivault",
				"--root-key-id", "transit/keys/test-key",
				"--leaf-key-id", "transit/keys/leaf-key",
				"--vault-address", "http://vault:8200",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "token is required for HashiVault KMS",
		},
		{
			name: "HashiVault KMS without address",
			args: []string{
				"--kms-type", "hashivault",
				"--root-key-id", "transit/keys/test-key",
				"--leaf-key-id", "transit/keys/leaf-key",
				"--vault-token", "test-token",
				"--root-template", rootTmplPath,
				"--leaf-template", leafTmplPath,
			},
			wantError: true,
			errMsg:    "address is required for HashiVault KMS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.ConfigureLogger("prod")
			cmd := &cobra.Command{
				Use:  "test",
				RunE: runCreate,
			}

			cmd.Flags().String("kms-type", "", "KMS provider type")
			cmd.Flags().String("aws-region", "", "AWS KMS region")
			cmd.Flags().String("azure-tenant-id", "", "Azure KMS tenant ID")
			cmd.Flags().String("gcp-credentials-file", "", "Path to credentials file for GCP KMS")
			cmd.Flags().String("vault-token", "", "HashiVault token")
			cmd.Flags().String("vault-address", "", "HashiVault server address")

			cmd.Flags().String("root-key-id", "", "KMS key identifier for root certificate")
			cmd.Flags().String("root-template", "", "Path to root certificate template")
			cmd.Flags().String("root-cert", "root.pem", "Output path for root certificate")

			cmd.Flags().String("intermediate-key-id", "", "KMS key identifier for intermediate certificate")
			cmd.Flags().String("intermediate-template", "", "Path to intermediate certificate template")
			cmd.Flags().String("intermediate-cert", "intermediate.pem", "Output path for intermediate certificate")

			cmd.Flags().String("leaf-key-id", "", "KMS key identifier for leaf certificate")
			cmd.Flags().String("leaf-template", "", "Path to leaf certificate template")
			cmd.Flags().String("leaf-cert", "leaf.pem", "Output path for leaf certificate")

			viper.Reset()
			viper.BindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
			viper.BindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
			viper.BindPFlag("azure-tenant-id", cmd.Flags().Lookup("azure-tenant-id"))
			viper.BindPFlag("gcp-credentials-file", cmd.Flags().Lookup("gcp-credentials-file"))
			viper.BindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
			viper.BindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))
			viper.BindPFlag("vault-token", cmd.Flags().Lookup("vault-token"))
			viper.BindPFlag("vault-address", cmd.Flags().Lookup("vault-address"))
			viper.BindPFlag("root-template", cmd.Flags().Lookup("root-template"))
			viper.BindPFlag("leaf-template", cmd.Flags().Lookup("leaf-template"))
			viper.BindPFlag("intermediate-template", cmd.Flags().Lookup("intermediate-template"))

			switch tt.name {
			case "invalid KMS type":
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			case "missing_root_template":
				viper.Set("kms-type", "awskms")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", "nonexistent.json")
				viper.Set("leaf-template", leafTmplPath)
			case "missing_leaf_template":
				viper.Set("kms-type", "awskms")
				viper.Set("leaf-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", "nonexistent.json")
			case "GCP_KMS_with_credentials_file":
				viper.Set("kms-type", "gcpkms")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			case "Azure_KMS_without_tenant_ID":
				viper.Set("kms-type", "azurekms")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			case "AWS_KMS_test":
				viper.Set("kms-type", "awskms")
				viper.Set("aws-region", "us-west-2")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			case "HashiVault_KMS_without_token":
				viper.Set("kms-type", "hashivault")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			case "HashiVault_KMS_without_address":
				viper.Set("kms-type", "hashivault")
				viper.Set("root-key-id", "dummy-key")
				viper.Set("vault-token", "dummy-token")
				viper.Set("root-template", rootTmplPath)
				viper.Set("leaf-template", leafTmplPath)
			}

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantError {
				require.Error(t, err)
				if tt.name == "AWS KMS test" {
					assert.True(t,
						strings.Contains(err.Error(), "get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found") ||
							strings.Contains(err.Error(), "NotFoundException: Alias arn:aws:kms:us-west-2:") ||
							strings.Contains(err.Error(), "operation error KMS: GetPublicKey"),
						"Expected AWS credentials or key not found error, got: %v", err)
				} else {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateCommand(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}

	cmd.Flags().String("kms-type", "", "KMS type")
	cmd.Flags().String("aws-region", "", "AWS KMS region")
	cmd.Flags().String("root-key-id", "", "Root key ID")
	cmd.Flags().String("leaf-key-id", "", "Leaf key ID")

	viper.Reset()
	viper.BindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
	viper.BindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
	viper.BindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
	viper.BindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))

	err := cmd.Execute()
	require.NoError(t, err)

	err = cmd.ParseFlags([]string{
		"--kms-type", "awskms",
		"--aws-region", "us-west-2",
		"--root-key-id", "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"--leaf-key-id", "arn:aws:kms:us-west-2:123456789012:key/9876fedc-ba98-7654-3210-fedcba987654",
	})
	require.NoError(t, err)

	assert.Equal(t, "awskms", viper.GetString("kms-type"))
	assert.Equal(t, "us-west-2", viper.GetString("aws-region"))
	assert.Equal(t, "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", viper.GetString("root-key-id"))
	assert.Equal(t, "arn:aws:kms:us-west-2:123456789012:key/9876fedc-ba98-7654-3210-fedcba987654", viper.GetString("leaf-key-id"))
}

func TestRootCommand(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	require.NoError(t, err)

	rootCmd.SetArgs([]string{"unknown"})
	err = rootCmd.Execute()
	require.Error(t, err)
}

func setupTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}

	cmd.Flags().String("kms-type", "", "KMS type")
	cmd.Flags().String("aws-region", "", "AWS KMS region")
	cmd.Flags().String("azure-tenant-id", "", "Azure KMS tenant ID")
	cmd.Flags().String("vault-token", "", "HashiVault token")
	cmd.Flags().String("vault-address", "", "HashiVault address")
	cmd.Flags().String("root-key-id", "", "Root key ID")
	cmd.Flags().String("leaf-key-id", "", "Leaf key ID")
	cmd.Flags().String("root-template", "", "Root template path")
	cmd.Flags().String("leaf-template", "", "Leaf template path")

	return cmd
}

func TestEnvironmentVariableOverrides(t *testing.T) {
	oldEnv := make(map[string]string)
	envVars := []string{
		"KMS_TYPE",
		"AWS_REGION",
		"AZURE_TENANT_ID",
		"GCP_CREDENTIALS_FILE",
		"VAULT_TOKEN",
		"VAULT_ADDR",
		"KMS_ROOT_KEY_ID",
		"KMS_INTERMEDIATE_KEY_ID",
		"KMS_LEAF_KEY_ID",
	}
	for _, env := range envVars {
		oldEnv[env] = os.Getenv(env)
	}

	defer func() {
		for env, value := range oldEnv {
			if value == "" {
				os.Unsetenv(env)
			} else {
				os.Setenv(env, value)
			}
		}
	}()

	tests := []struct {
		name       string
		envVars    map[string]string
		flags      map[string]string
		wantValues map[string]string
	}{
		{
			name: "environment_overrides_flags",
			envVars: map[string]string{
				"KMS_TYPE":        "awskms",
				"AWS_REGION":      "us-east-1",
				"KMS_ROOT_KEY_ID": "env-root-key",
				"KMS_LEAF_KEY_ID": "env-leaf-key",
			},
			flags: map[string]string{
				"kms-type":    "gcpkms",
				"aws-region":  "us-west-2",
				"root-key-id": "flag-root-key",
				"leaf-key-id": "flag-leaf-key",
			},
			wantValues: map[string]string{
				"kms-type":    "awskms",
				"aws-region":  "us-east-1",
				"root-key-id": "env-root-key",
				"leaf-key-id": "env-leaf-key",
			},
		},
		{
			name: "azure_kms_environment",
			envVars: map[string]string{
				"KMS_TYPE":        "azurekms",
				"AZURE_TENANT_ID": "env-tenant-id",
				"KMS_ROOT_KEY_ID": "azurekms:name=env-key;vault=env-vault",
				"KMS_LEAF_KEY_ID": "azurekms:name=env-leaf;vault=env-vault",
			},
			flags: map[string]string{
				"azure-tenant-id": "flag-tenant-id",
				"root-key-id":     "flag-root-key",
				"leaf-key-id":     "flag-leaf-key",
			},
			wantValues: map[string]string{
				"kms-type":        "azurekms",
				"azure-tenant-id": "env-tenant-id",
				"root-key-id":     "azurekms:name=env-key;vault=env-vault",
				"leaf-key-id":     "azurekms:name=env-leaf;vault=env-vault",
			},
		},
		{
			name: "hashivault_kms_environment",
			envVars: map[string]string{
				"KMS_TYPE":        "hashivault",
				"VAULT_TOKEN":     "env-token",
				"VAULT_ADDR":      "http://env-vault:8200",
				"KMS_ROOT_KEY_ID": "transit/keys/env-key",
				"KMS_LEAF_KEY_ID": "transit/keys/env-leaf",
			},
			flags: map[string]string{
				"vault-token":   "flag-token",
				"vault-address": "http://flag-vault:8200",
				"root-key-id":   "flag-root-key",
				"leaf-key-id":   "flag-leaf-key",
			},
			wantValues: map[string]string{
				"kms-type":      "hashivault",
				"vault-token":   "env-token",
				"vault-address": "http://env-vault:8200",
				"root-key-id":   "transit/keys/env-key",
				"leaf-key-id":   "transit/keys/env-leaf",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, env := range envVars {
				os.Unsetenv(env)
			}
			viper.Reset()

			viper.AutomaticEnv()
			viper.SetEnvPrefix("")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

			mustBindEnv("kms-type", "KMS_TYPE")
			mustBindEnv("aws-region", "AWS_REGION")
			mustBindEnv("azure-tenant-id", "AZURE_TENANT_ID")
			mustBindEnv("vault-token", "VAULT_TOKEN")
			mustBindEnv("vault-address", "VAULT_ADDR")
			mustBindEnv("root-key-id", "KMS_ROOT_KEY_ID")
			mustBindEnv("leaf-key-id", "KMS_LEAF_KEY_ID")

			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			for k, v := range tt.flags {
				viper.SetDefault(k, v)
			}

			for k, want := range tt.wantValues {
				got := viper.GetString(k)
				assert.Equal(t, want, got, "key %s", k)
			}
		})
	}
}

func TestTemplateValidationInRunCreate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "template-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	validTemplate := `{
		"subject": {
			"commonName": "Test CA"
		},
		"issuer": {
			"commonName": "Test CA"
		},
		"certLife": "8760h",
		"keyUsage": ["certSign", "crlSign"],
		"basicConstraints": {
			"isCA": true,
			"maxPathLen": 1
		}
	}`

	invalidTemplate := `{
		"invalid": json,
	}`

	validPath := filepath.Join(tmpDir, "valid.json")
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	nonexistentPath := filepath.Join(tmpDir, "nonexistent.json")

	err = os.WriteFile(validPath, []byte(validTemplate), 0600)
	require.NoError(t, err)
	err = os.WriteFile(invalidPath, []byte(invalidTemplate), 0600)
	require.NoError(t, err)

	tests := []struct {
		name      string
		flags     []string
		wantError string
	}{
		{
			name: "valid_template_paths",
			flags: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-leaf-key",
				"--root-template", validPath,
				"--leaf-template", validPath,
			},
			wantError: "error getting root public key",
		},
		{
			name: "nonexistent_root_template",
			flags: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-leaf-key",
				"--root-template", nonexistentPath,
				"--leaf-template", validPath,
			},
			wantError: "template not found",
		},
		{
			name: "invalid_root_template_json",
			flags: []string{
				"--kms-type", "awskms",
				"--aws-region", "us-west-2",
				"--root-key-id", "alias/test-key",
				"--leaf-key-id", "alias/test-leaf-key",
				"--root-template", invalidPath,
				"--leaf-template", validPath,
			},
			wantError: "invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.AutomaticEnv()
			viper.SetEnvPrefix("")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

			cmd := setupTestCommand()
			cmd.RunE = runCreate

			mustBindPFlag("kms-type", cmd.Flags().Lookup("kms-type"))
			mustBindPFlag("aws-region", cmd.Flags().Lookup("aws-region"))
			mustBindPFlag("root-key-id", cmd.Flags().Lookup("root-key-id"))
			mustBindPFlag("leaf-key-id", cmd.Flags().Lookup("leaf-key-id"))
			mustBindPFlag("root-template", cmd.Flags().Lookup("root-template"))
			mustBindPFlag("leaf-template", cmd.Flags().Lookup("leaf-template"))

			cmd.SetArgs(tt.flags)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}
