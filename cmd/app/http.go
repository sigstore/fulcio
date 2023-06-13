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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	legacy_gw "github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type httpServer struct {
	*http.Server
	httpServerEndpoint string
}

func extractOIDCTokenFromAuthHeader(_ context.Context, req *http.Request) metadata.MD {
	token := strings.Replace(req.Header.Get("Authorization"), "Bearer ", "", 1)
	return metadata.Pairs(server.MetadataOIDCTokenKey, token)
}

func createHTTPServer(ctx context.Context, serverEndpoint string, grpcServer, legacyGRPCServer *grpcServer) httpServer {
	mux := runtime.NewServeMux(runtime.WithMetadata(extractOIDCTokenFromAuthHeader),
		runtime.WithForwardResponseOption(setResponseCodeModifier))

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
	handler := server.WithMaxBytes(mux, maxMsgSize)
	handler = promhttp.InstrumentHandlerDuration(server.MetricLatency, handler)
	handler = promhttp.InstrumentHandlerCounter(server.RequestsCount, handler)

	// enable CORS
	// cors.Default() configures to accept requests for all domains
	handler = cors.Default().Handler(handler)

	api := http.Server{
		Addr:    serverEndpoint,
		Handler: handler,

		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return httpServer{&api, serverEndpoint}
}

func (h httpServer) startListener() {
	log.Logger.Infof("listening on http at %s", h.httpServerEndpoint)
	go func() {
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Logger.Fatal(err)
		}
	}()
}

func setResponseCodeModifier(ctx context.Context, w http.ResponseWriter, _ proto.Message) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	// set SCT if present ahead of modifying response code
	if vals := md.HeaderMD.Get(server.SCTMetadataKey); len(vals) > 0 {
		delete(md.HeaderMD, server.SCTMetadataKey)
		delete(w.Header(), "Grpc-Metadata-sct")
		w.Header().Set("SCT", vals[0])
	}

	// strip all GRPC response headers
	for headerKey := range w.Header() {
		if strings.HasPrefix(headerKey, "Grpc-") {
			delete(w.Header(), headerKey)
		}
	}

	// set http status code
	if vals := md.HeaderMD.Get(server.HTTPResponseCodeMetadataKey); len(vals) > 0 {
		code, err := strconv.Atoi(vals[0])
		if err != nil {
			return err
		}
		// delete the headers to not expose any grpc-metadata in http response
		delete(md.HeaderMD, server.HTTPResponseCodeMetadataKey)
		w.WriteHeader(code)
	}

	return nil
}
