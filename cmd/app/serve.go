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

		// Crash if we can't parse the config correctly
		if err := config.Load(viper.GetString("config-path")); err != nil {
			log.Logger.Panic(err)
		}
		server.EnabledListeners = []string{"http"}

		server.ConfigureAPI()

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
