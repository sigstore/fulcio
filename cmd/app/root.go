// Copyright 2021 The Sigstore Authors.
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

package app

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/log"
)

var (
	logType string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fulcio",
	Short: "Fulcio",
	Long:  "Fulcio generates certificates that can be used to sign software artifacts",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ctx context.Context) {
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logType, "log_type", "dev", "logger type to use (dev/prod)")
	rootCmd.PersistentFlags().String("ca", "", "googleca | pkcs11ca | ephemeralca (for testing)")
	rootCmd.PersistentFlags().String("aws-hsm-root-ca-path", "", "Path to root CA on disk (only used with AWS HSM)")
	rootCmd.PersistentFlags().String("gcp_private_ca_parent", "", "private ca parent: /projects/<project>/locations/<location>/<name> (only used with --ca googleca)")
	rootCmd.PersistentFlags().String("gcp_private_ca_version", "v1", "private ca version: [v1|v1beta1] (only used with --ca googleca)")
	rootCmd.PersistentFlags().String("hsm-caroot-id", "", "HSM ID for Root CA (only used with --ca pkcs11ca)")
	rootCmd.PersistentFlags().String("ct-log-url", "http://localhost:6962/test", "host and path (with log prefix at the end) to the ct log")
	rootCmd.PersistentFlags().String("config-path", "/etc/fulcio-config/config.json", "path to fulcio config json")
	rootCmd.PersistentFlags().String("pkcs11-config-path", "config/crypto11.conf", "path to fulcio pkcs11 config file")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}
}
