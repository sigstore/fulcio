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

	"github.com/goadesign/goa/grpc/middleware"
	ctclient "github.com/google/certificate-transparency-go/client"
	grpcmw "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/fulcio/pkg/ca"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	gw_legacy "github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/log"
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

func createGRPCServer(ctClient *ctclient.LogClient, baseca ca.CertificateAuthority, ip identity.IssuerPool) (*grpcServer, error) {
	logger, opts := log.SetupGRPCLogging()

	myServer := grpc.NewServer(grpc.UnaryInterceptor(
		grpcmw.ChainUnaryServer(
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandlerContext(panicRecoveryHandler)), // recovers from per-transaction panics elegantly, so put it first
			middleware.UnaryRequestID(middleware.UseXRequestIDMetadataOption(true), middleware.XRequestMetadataLimitOption(128)),
			grpc_zap.UnaryServerInterceptor(logger, opts...),
			grpc_prometheus.UnaryServerInterceptor,
		)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)))

	grpcCAServer := api.NewGRPCCAServer(ctClient, baseca, ip)
	// Register your gRPC service implementations.
	gw.RegisterCAServer(myServer, grpcCAServer)

	grpcServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("grpc-host"), viper.GetString("grpc-port"))
	return &grpcServer{myServer, grpcServerEndpoint, grpcCAServer}, nil
}

func (g *grpcServer) setupPrometheus(reg *prometheus.Registry) {
	grpcMetrics := grpc_prometheus.DefaultServerMetrics
	grpcMetrics.EnableHandlingTimeHistogram()
	reg.MustRegister(grpcMetrics, api.MetricLatency, api.RequestsCount)
	grpc_prometheus.Register(g.Server)
}

func (g *grpcServer) startTCPListener() {
	go func() {
		lis, err := net.Listen("tcp", g.grpcServerEndpoint)
		if err != nil {
			log.Logger.Fatal(err)
		}
		defer lis.Close()

		tcpAddr := lis.Addr().(*net.TCPAddr)
		g.grpcServerEndpoint = fmt.Sprintf("%v:%d", tcpAddr.IP, tcpAddr.Port)
		log.Logger.Infof("listening on grpc at %s", g.grpcServerEndpoint)

		log.Logger.Fatal(g.Server.Serve(lis))
	}()
}

func (g *grpcServer) startUnixListener() {
	go func() {
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

func createLegacyGRPCServer(v2Server gw.CAServer) (*grpcServer, error) {
	logger, opts := log.SetupGRPCLogging()

	myServer := grpc.NewServer(grpc.UnaryInterceptor(
		grpcmw.ChainUnaryServer(
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandlerContext(panicRecoveryHandler)), // recovers from per-transaction panics elegantly, so put it first
			middleware.UnaryRequestID(middleware.UseXRequestIDMetadataOption(true), middleware.XRequestMetadataLimitOption(128)),
			grpc_zap.UnaryServerInterceptor(logger, opts...),
			grpc_prometheus.UnaryServerInterceptor,
		)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)))

	legacyGRPCCAServer := api.NewLegacyGRPCCAServer(v2Server)

	// Register your gRPC service implementations.
	gw_legacy.RegisterCAServer(myServer, legacyGRPCCAServer)

	return &grpcServer{myServer, LegacyUnixDomainSocket, v2Server}, nil
}

func panicRecoveryHandler(ctx context.Context, p interface{}) error {
	log.ContextLogger(ctx).Error(p)
	return fmt.Errorf("panic: %v", p)
}
