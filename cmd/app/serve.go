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
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sigstore/fulcio/pkg/api"
	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/ca/fileca"
	googlecav1 "github.com/sigstore/fulcio/pkg/ca/googleca/v1"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const serveCmdEnvPrefix = "FULCIO_SERVE"

var serveCmdConfigFilePath string

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "start http server with configured api",
		Long:  `Starts a http server and serves the configured api`,
		Run:   runServeCmd,
	}

	cmd.Flags().StringVarP(&serveCmdConfigFilePath, "config", "c", "", "config file containing all settings")
	cmd.Flags().String("log_type", "dev", "logger type to use (dev/prod)")
	cmd.Flags().String("ca", "", "googleca | pkcs11ca | fileca | ephemeralca (for testing)")
	cmd.Flags().String("aws-hsm-root-ca-path", "", "Path to root CA on disk (only used with AWS HSM)")
	cmd.Flags().String("gcp_private_ca_parent", "", "private ca parent: /projects/<project>/locations/<location>/<name> (only used with --ca googleca)")
	cmd.Flags().String("hsm-caroot-id", "", "HSM ID for Root CA (only used with --ca pkcs11ca)")
	cmd.Flags().String("ct-log-url", "http://localhost:6962/test", "host and path (with log prefix at the end) to the ct log")
	cmd.Flags().String("config-path", "/etc/fulcio-config/config.json", "path to fulcio config json")
	cmd.Flags().String("pkcs11-config-path", "config/crypto11.conf", "path to fulcio pkcs11 config file")
	cmd.Flags().String("fileca-cert", "", "Path to CA certificate")
	cmd.Flags().String("fileca-key", "", "Path to CA encrypted private key")
	cmd.Flags().String("fileca-key-passwd", "", "Password to decrypt CA private key")
	cmd.Flags().Bool("fileca-watch", true, "Watch filesystem for updates")
	cmd.Flags().String("host", "0.0.0.0", "The host on which to serve requests")
	cmd.Flags().String("port", "8080", "The port on which to serve requests")

	return cmd
}

func runServeCmd(cmd *cobra.Command, args []string) {
	// If a config file is provided, modify the viper config to locate and read it
	if err := checkServeCmdConfigFile(); err != nil {
		log.Logger.Fatal(err)
	}

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Logger.Fatal(err)
	}

	// Allow recognition of environment variables such as FULCIO_SERVE_CA etc.
	viper.SetEnvPrefix(serveCmdEnvPrefix)
	viper.AutomaticEnv()

	switch viper.GetString("ca") {
	case "":
		log.Logger.Fatal("required flag \"ca\" not set")

	case "pkcs11ca":
		if !viper.IsSet("hsm-caroot-id") {
			log.Logger.Fatal("hsm-caroot-id must be set when using pkcs11ca")
		}

	case "googleca":
		if !viper.IsSet("gcp_private_ca_parent") {
			log.Logger.Fatal("gcp_private_ca_parent must be set when using googleca")
		}
		if viper.IsSet("gcp_private_ca_version") {
			// There's a MarkDeprecated function in cobra/pflags, but it doesn't use log.Logger
			log.Logger.Warn("gcp_private_ca_version is deprecated and will soon be removed; please remove it")
		}

	case "fileca":
		if !viper.IsSet("fileca-cert") {
			log.Logger.Fatal("fileca-cert must be set to certificate path when using fileca")
		}
		if !viper.IsSet("fileca-key") {
			log.Logger.Fatal("fileca-key must be set to private key path when using fileca")
		}
		if !viper.IsSet("fileca-key-passwd") {
			log.Logger.Fatal("fileca-key-passwd must be set to encryption password for private key file when using fileca")
		}

	case "ephemeralca":
		// this is a no-op since this is a self-signed in-memory CA for testing
	default:
		log.Logger.Fatalf("--ca=%s is not a valid selection. Try: pkcs11ca, googleca, fileca, or ephemeralca", viper.GetString("ca"))
	}

	// Setup the logger to dev/prod
	log.ConfigureLogger(viper.GetString("log_type"))

	// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
	_ = flag.CommandLine.Parse([]string{})

	cp := viper.GetString("config-path")
	cfg, err := config.Load(cp)
	if err != nil {
		log.Logger.Fatalf("error loading --config-path=%s: %v", cp, err)
	}

	var baseca certauth.CertificateAuthority
	switch viper.GetString("ca") {
	case "googleca":
		baseca, err = googlecav1.NewCertAuthorityService(cmd.Context(), viper.GetString("gcp_private_ca_parent"))
	case "pkcs11ca":
		params := x509ca.Params{
			ConfigPath: viper.GetString("pkcs11-config-path"),
			RootID:     viper.GetString("hsm-caroot-id"),
		}
		if viper.IsSet("aws-hsm-root-ca-path") {
			path := viper.GetString("aws-hsm-root-ca-path")
			params.CAPath = &path
		}
		baseca, err = x509ca.NewX509CA(params)
	case "fileca":
		certFile := viper.GetString("fileca-cert")
		keyFile := viper.GetString("fileca-key")
		keyPass := viper.GetString("fileca-key-passwd")
		watch := viper.GetBool("fileca-watch")
		baseca, err = fileca.NewFileCA(certFile, keyFile, keyPass, watch)
	case "ephemeralca":
		baseca, err = ephemeralca.NewEphemeralCA()
	default:
		err = fmt.Errorf("invalid value for configured CA: %v", baseca)
	}
	if err != nil {
		log.Logger.Fatal(err)
	}

	prom := http.Server{
		Addr:    ":2112",
		Handler: promhttp.Handler(),
	}
	go func() {
		_ = prom.ListenAndServe()
	}()

	host, port := viper.GetString("host"), viper.GetString("port")
	log.Logger.Infof("%s:%s", host, port)

	var ctClient *ctl.Client
	if logURL := viper.GetString("ct-log-url"); logURL != "" {
		ctClient = ctl.New(logURL)
	}

	var handler http.Handler
	{
		handler = api.New(ctClient, baseca)

		// Inject dependencies
		withDependencies := func(inner http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

				// For each request, infuse context with our snapshot of the FulcioConfig.
				// TODO(mattmoor): Consider periodically (every minute?) refreshing the ConfigMap
				// from disk, so that we don't need to cycle pods to pick up config updates.
				// Alternately we could take advantage of Knative's configmap watcher.
				ctx = config.With(ctx, cfg)

				inner.ServeHTTP(rw, r.WithContext(ctx))
			})
		}
		handler = withDependencies(handler)

		// Instrument Prometheus metrics
		handler = promhttp.InstrumentHandlerDuration(api.MetricLatency, handler)

		// Limit request size
		handler = api.WithMaxBytes(handler, 1<<22) // 4MiB
	}

	api := http.Server{
		Addr:    host + ":" + port,
		Handler: handler,

		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Logger.Fatal(err)
	}
}

func checkServeCmdConfigFile() error {
	if serveCmdConfigFilePath != "" {
		if _, err := os.Stat(serveCmdConfigFilePath); err != nil {
			return errors.Wrap(err, "unable to stat config file provided")
		}
		abspath, err := filepath.Abs(serveCmdConfigFilePath)
		if err != nil {
			return errors.Wrap(err, "unable to determine absolute path of config file provided")
		}
		extWithDot := filepath.Ext(abspath)
		ext := strings.TrimPrefix(extWithDot, ".")
		var extIsValid bool
		for _, validExt := range viper.SupportedExts {
			if ext == validExt {
				extIsValid = true
				break
			}
		}
		if !extIsValid {
			return fmt.Errorf("config file must have one of the following extensions: %s", strings.Join(viper.SupportedExts, ", "))
		}
		viper.SetConfigName(strings.TrimSuffix(filepath.Base(abspath), extWithDot))
		viper.SetConfigType(ext)
		viper.AddConfigPath(filepath.Dir(serveCmdConfigFilePath))
		if err := viper.ReadInConfig(); err != nil {
			return errors.Wrap(err, "unable to parse config file provided")
		}
	}
	return nil
}
