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
	"net/http"

	"github.com/go-openapi/loads"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/generated/restapi"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start http server with configured api",
	Long:  `Starts a http server and serves the configured api`,
	Run: func(cmd *cobra.Command, args []string) {

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

		doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		server := restapi.NewServer(operations.NewFulcioServerAPI(doc))
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
		}()

		cfg, err := config.Load(viper.GetString("config-path"))
		if err != nil {
			log.Logger.Fatalf("error loading config: %v", err)
		}

		server.EnabledListeners = []string{"http"}

		server.ConfigureAPI()

		h := server.GetHandler()
		server.SetHandler(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// For each request, infuse context with our snapshot of the FulcioConfig.
			// TODO(mattmoor): Consider periodically (every minute?) refreshing the ConfigMap
			// from disk, so that we don't need to cycle pods to pick up config updates.
			// Alternately we could take advantage of Knative's configmap watcher.
			ctx = config.With(ctx, cfg)

			h.ServeHTTP(rw, r.WithContext(ctx))
		}))

		http.Handle("/metrics", promhttp.Handler())
		go func() {
			_ = http.ListenAndServe(":2112", nil)
		}()

		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
