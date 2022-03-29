// Copyright 2022 The Sigstore Authors.
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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/api"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	legacy_gw "github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type httpServer struct {
	*http.Server
	httpServerEndpoint string
}

func extractOIDCTokenFromAuthHeader(ctx context.Context, req *http.Request) metadata.MD {
	token := strings.Replace(req.Header.Get("Authorization"), "Bearer ", "", 1)
	return metadata.Pairs(api.MetadataOIDCTokenKey, token)
}

func createHTTPServer(ctx context.Context, grpcServer, legacyGRPCServer *grpcServer) httpServer {
	mux := runtime.NewServeMux(runtime.WithMetadata(extractOIDCTokenFromAuthHeader))

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := gw.RegisterCAHandlerFromEndpoint(ctx, mux, grpcServer.grpcServerEndpoint, opts); err != nil {
		log.Logger.Fatal(err)
	}

	if legacyGRPCServer != nil {
		endpoint := fmt.Sprintf("unix:%v", legacyGRPCServer.grpcServerEndpoint)
		if err := legacy_gw.RegisterCAHandlerFromEndpoint(ctx, mux, endpoint, opts); err != nil {
			log.Logger.Fatal(err)
		}
	}

	// Limit request size
	handler := api.WithMaxBytes(mux, maxMsgSize)
	httpServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("http-host"), viper.GetString("http-port"))

	api := http.Server{
		Addr:    httpServerEndpoint,
		Handler: handler,

		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return httpServer{&api, httpServerEndpoint}
}

func (h httpServer) startListener() {
	log.Logger.Infof("listening on http at %s", h.httpServerEndpoint)
	go func() {
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Logger.Fatal(err)
		}
	}()
}
