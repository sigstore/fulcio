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
	"net"
	"os"
	"runtime"

	"github.com/goadesign/goa/grpc/middleware"
	ctclient "github.com/google/certificate-transparency-go/client"
	grpcmw "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/config"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	gw_legacy "github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/server"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

const (
	LegacyUnixDomainSocket = "@fulcio-legacy-grpc-socket"
)

type grpcServer struct {
	*grpc.Server
	grpcServerEndpoint string
	caService          gw.CAServer
}

func PassFulcioConfigThruContext(cfg *config.FulcioConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// For each request, infuse context with our snapshot of the FulcioConfig.
		// TODO(mattmoor): Consider periodically (every minute?) refreshing the ConfigMap
		// from disk, so that we don't need to cycle pods to pick up config updates.
		// Alternately we could take advantage of Knative's configmap watcher.
		ctx = config.With(ctx, cfg)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Calls the inner handler
		return handler(ctx, req)
	}
}

func createGRPCServer(cfg *config.FulcioConfig, ctClient *ctclient.LogClient, baseca ca.CertificateAuthority) (*grpcServer, error) {
	logger, opts := log.SetupGRPCLogging()

	myServer := grpc.NewServer(grpc.UnaryInterceptor(
		grpcmw.ChainUnaryServer(
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandlerContext(panicRecoveryHandler)), // recovers from per-transaction panics elegantly, so put it first
			middleware.UnaryRequestID(middleware.UseXRequestIDMetadataOption(true), middleware.XRequestMetadataLimitOption(128)),
			grpc_zap.UnaryServerInterceptor(logger, opts...),
			PassFulcioConfigThruContext(cfg),
			grpc_prometheus.UnaryServerInterceptor,
		)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)))

	grpcCAServer := server.NewGRPCCAServer(ctClient, baseca)
	// Register your gRPC service implementations.
	gw.RegisterCAServer(myServer, grpcCAServer)

	grpcServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("grpc-host"), viper.GetString("grpc-port"))
	return &grpcServer{myServer, grpcServerEndpoint, grpcCAServer}, nil
}

func (g *grpcServer) setupPrometheus(reg *prometheus.Registry) {
	grpcMetrics := grpc_prometheus.DefaultServerMetrics
	grpcMetrics.EnableHandlingTimeHistogram()
	reg.MustRegister(grpcMetrics, server.MetricLatency, server.RequestsCount)
	grpc_prometheus.Register(g.Server)
}

func (g *grpcServer) startTCPListener() {
	// lis is closed by g.Server.Serve() upon exit
	lis, err := net.Listen("tcp", g.grpcServerEndpoint)
	if err != nil {
		log.Logger.Fatal(err)
	}

	g.grpcServerEndpoint = lis.Addr().String()
	log.Logger.Infof("listening on grpc at %s", g.grpcServerEndpoint)
	go func() {
		if err := g.Server.Serve(lis); err != nil {
			log.Logger.Errorf("error shutting down grpcServer: %w", err)
		}
	}()
}

func (g *grpcServer) startUnixListener() {
	go func() {
		if runtime.GOOS != "linux" {
			// As MacOS doesn't have abstract unix domain sockets the file
			// created by a previous run needs to be explicitly removed
			if err := os.RemoveAll(LegacyUnixDomainSocket); err != nil {
				log.Logger.Fatal(err)
			}
		}

		unixAddr, err := net.ResolveUnixAddr("unix", LegacyUnixDomainSocket)
		if err != nil {
			log.Logger.Fatal(err)
		}
		lis, err := net.ListenUnix("unix", unixAddr)
		if err != nil {
			log.Logger.Fatal(err)
		}
		defer lis.Close()

		log.Logger.Infof("listening on grpc at %s", unixAddr.String())

		log.Logger.Fatal(g.Server.Serve(lis))
	}()
}

func createLegacyGRPCServer(cfg *config.FulcioConfig, v2Server gw.CAServer) (*grpcServer, error) {
	logger, opts := log.SetupGRPCLogging()

	myServer := grpc.NewServer(grpc.UnaryInterceptor(
		grpcmw.ChainUnaryServer(
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandlerContext(panicRecoveryHandler)), // recovers from per-transaction panics elegantly, so put it first
			middleware.UnaryRequestID(middleware.UseXRequestIDMetadataOption(true), middleware.XRequestMetadataLimitOption(128)),
			grpc_zap.UnaryServerInterceptor(logger, opts...),
			PassFulcioConfigThruContext(cfg),
			grpc_prometheus.UnaryServerInterceptor,
		)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)))

	legacyGRPCCAServer := server.NewLegacyGRPCCAServer(v2Server)

	// Register your gRPC service implementations.
	gw_legacy.RegisterCAServer(myServer, legacyGRPCCAServer)

	return &grpcServer{myServer, LegacyUnixDomainSocket, v2Server}, nil
}

func panicRecoveryHandler(ctx context.Context, p interface{}) error {
	log.ContextLogger(ctx).Error(p)
	return fmt.Errorf("panic: %v", p)
}
