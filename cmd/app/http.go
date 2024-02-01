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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	legacy_gw "github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/server"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
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
	opts := []grpc.DialOption{}
	if grpcServer.ExposesGRPCTLS() {
		/* #nosec G402 */ // InsecureSkipVerify is only used for the HTTP server to call the TLS-enabled grpc endpoint.
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	cc, err := grpc.Dial(grpcServer.grpcServerEndpoint, opts...)
	if err != nil {
		log.Logger.Fatal(err)
	}

	mux := runtime.NewServeMux(runtime.WithMetadata(extractOIDCTokenFromAuthHeader),
		runtime.WithForwardResponseOption(setResponseCodeModifier),
		runtime.WithHealthzEndpoint(health.NewHealthClient(cc)))

	if err := gw.RegisterCAHandlerFromEndpoint(ctx, mux, grpcServer.grpcServerEndpoint, opts); err != nil {
		log.Logger.Fatal(err)
	}

	if legacyGRPCServer != nil {
		endpoint := fmt.Sprintf("unix:%v", legacyGRPCServer.grpcServerEndpoint)
		// we are connecting over a unix domain socket, therefore we won't ever need TLS
		unixDomainSocketOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		if err := legacy_gw.RegisterCAHandlerFromEndpoint(ctx, mux, endpoint, unixDomainSocketOpts); err != nil {
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
		IdleTimeout:       viper.GetDuration("idle-connection-timeout"),
	}
	return httpServer{&api, serverEndpoint}
}

func (h httpServer) startListener(wg *sync.WaitGroup) {
	log.Logger.Infof("listening on http at %s", h.httpServerEndpoint)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		// received an interrupt signal, shut down
		if err := h.Shutdown(context.Background()); err != nil {
			// error from closing listeners, or context timeout
			log.Logger.Errorf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
		log.Logger.Info("stopped http server")
	}()

	wg.Add(1)
	go func() {
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Logger.Fatal(err)
		}
		<-idleConnsClosed
		wg.Done()
		log.Logger.Info("http server shutdown")
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
