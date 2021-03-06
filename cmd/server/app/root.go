/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/spf13/viper"
)

var cfgFile string
var logType string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fulcio-server",
	Short: "Fulcio",
	Long:  "Fulcio generates certificates that can be used to sign software artifacts",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig(cmd)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logType, "log_type", "dev", "logger type to use (dev/prod)")

	rootCmd.PersistentFlags().String("gcp_private_ca_parent", "", "private ca parent: /projects/<project>/locations/<location>/<name>")
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig(cmd *cobra.Command) error {
	viper.SetEnvPrefix("fulcio")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// manually set all values provided from viper through pflag validation logic
	var changedFlags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed && viper.IsSet(f.Name) {
			changedFlags = append(changedFlags, f.Name)
		}
	})

	for _, flag := range changedFlags {
		val := viper.Get(flag)
		if err := cmd.Flags().Set(flag, fmt.Sprintf("%v", val)); err != nil {
			return err
		}
	}

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("fulcio-server")
		viper.SetConfigType("yaml")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
		default:
			return err
		}
	} else {
		log.Logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
	return nil
}
