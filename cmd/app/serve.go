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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sigstore/fulcio/pkg/api"
	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	googlecav1 "github.com/sigstore/fulcio/pkg/ca/googleca/v1"
	googlecav1beta1 "github.com/sigstore/fulcio/pkg/ca/googleca/v1beta1"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "start http server with configured api",
		Long:  `Starts a http server and serves the configured api`,
		Run:   runServeCmd,
	}

	cmd.Flags().String("log_type", "dev", "logger type to use (dev/prod)")
	cmd.Flags().String("ca", "", "googleca | pkcs11ca | ephemeralca (for testing)")
	cmd.Flags().String("aws-hsm-root-ca-path", "", "Path to root CA on disk (only used with AWS HSM)")
	cmd.Flags().String("gcp_private_ca_parent", "", "private ca parent: /projects/<project>/locations/<location>/<name> (only used with --ca googleca)")
	cmd.Flags().String("gcp_private_ca_version", "v1", "private ca version: [v1|v1beta1] (only used with --ca googleca)")
	cmd.Flags().String("hsm-caroot-id", "", "HSM ID for Root CA (only used with --ca pkcs11ca)")
	cmd.Flags().String("ct-log-url", "http://localhost:6962/test", "host and path (with log prefix at the end) to the ct log")
	cmd.Flags().String("config-path", "/etc/fulcio-config/config.json", "path to fulcio config json")
	cmd.Flags().String("pkcs11-config-path", "config/crypto11.conf", "path to fulcio pkcs11 config file")
	cmd.Flags().String("host", "0.0.0.0", "The host on which to serve requests")
	cmd.Flags().String("port", "8080", "The port on which to serve requests")

	err := cmd.MarkFlagRequired("ca")
	if err != nil {
		log.Logger.Fatal(`Failed to mark flag as required`)
	}

	return cmd
}

func runServeCmd(cmd *cobra.Command, args []string) {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Logger.Fatal(err)
	}

	switch viper.GetString("ca") {
	case "pkcs11ca":
		if !viper.IsSet("hsm-caroot-id") {
			log.Logger.Fatal("hsm-caroot-id must be set when using pkcs11ca")
		}

	case "googleca":
		if !viper.IsSet("gcp_private_ca_parent") {
			log.Logger.Fatal("gcp_private_ca_parent must be set when using googleca")
		}

	case "ephemeralca":
		// this is a no-op since this is a self-signed in-memory CA for testing
	default:
		log.Logger.Fatal("unknown CA: ", viper.GetString("ca"))
	}

	// Setup the logger to dev/prod
	log.ConfigureLogger(viper.GetString("log_type"))

	// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
	_ = flag.CommandLine.Parse([]string{})

	cfg, err := config.Load(viper.GetString("config-path"))
	if err != nil {
		log.Logger.Fatalf("error loading config: %v", err)
	}

	var baseca certauth.CertificateAuthority
	switch viper.GetString("ca") {
	case "googleca":
		version := viper.GetString("gcp_private_ca_version")
		switch version {
		case "v1":
			baseca, err = googlecav1.NewCertAuthorityService(cmd.Context(), viper.GetString("gcp_private_ca_parent"))
		case "v1beta1":
			baseca, err = googlecav1beta1.NewCertAuthorityService(cmd.Context(), viper.GetString("gcp_private_ca_parent"))
		default:
			err = fmt.Errorf("invalid value for gcp_private_ca_version: %v", version)
		}
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
	case "ephemeralca":
		baseca, err = ephemeralca.NewEphemeralCA()
	default:
		err = fmt.Errorf("invalid value for configured CA: %v", baseca)
	}
	if err != nil {
		log.Logger.Fatal(err)
	}

	decorateHandler := func(h http.Handler) http.Handler {
		// Wrap the inner func with instrumentation to get latencies
		// that get partitioned by 'code' and 'method'.
		return promhttp.InstrumentHandlerDuration(
			api.MetricLatency,
			http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

				// For each request, infuse context with our snapshot of the FulcioConfig.
				// TODO(mattmoor): Consider periodically (every minute?) refreshing the ConfigMap
				// from disk, so that we don't need to cycle pods to pick up config updates.
				// Alternately we could take advantage of Knative's configmap watcher.
				ctx = config.With(ctx, cfg)
				ctx = api.WithCA(ctx, baseca)
				ctx = api.WithCTLogURL(ctx, viper.GetString("ct-log-url"))

				h.ServeHTTP(rw, r.WithContext(ctx))
			}))
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
	api := http.Server{
		Addr:    host + ":" + port,
		Handler: decorateHandler(api.NewHandler()),
	}

	if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Logger.Fatal(err)
	}
}
