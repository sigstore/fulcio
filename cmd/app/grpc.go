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

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

type grpcServer struct {
	*grpc.Server
	grpcServerEndpoint string
}

func passFulcioConfigThruContext(cfg *config.FulcioConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// For each request, infuse context with our snapshot of the FulcioConfig.
		// TODO(mattmoor): Consider periodically (every minute?) refreshing the ConfigMap
		// from disk, so that we don't need to cycle pods to pick up config updates.
		// Alternately we could take advantage of Knative's configmap watcher.
		ctx = config.With(ctx, cfg)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Calls the prometheus handler
		return grpc_prometheus.UnaryServerInterceptor(ctx, req, info, handler)
	}
}

func createGRPCServer(cfg *config.FulcioConfig, ctClient ctl.Client, baseca ca.CertificateAuthority) grpcServer {
	myServer := grpc.NewServer(
		grpc.UnaryInterceptor(passFulcioConfigThruContext(cfg)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)),
	)

	grpcCAServer := api.NewGRPCCAServer(ctClient, baseca)
	// Register your gRPC service implementations.
	gw.RegisterCAServer(myServer, grpcCAServer)

	grpcServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("grpc-host"), viper.GetString("grpc-port"))
	return grpcServer{myServer, grpcServerEndpoint}
}

func (g grpcServer) setupPrometheus(reg *prometheus.Registry) {
	grpcMetrics := grpc_prometheus.NewServerMetrics()
	reg.MustRegister(grpcMetrics, api.MetricLatency, api.RequestsCount)

	grpc_prometheus.Register(g.Server)
}

func (g grpcServer) startListener() {
	log.Logger.Infof("listening on grpc at %s", g.grpcServerEndpoint)

	go func() {
		lis, err := net.Listen("tcp", g.grpcServerEndpoint)
		if err != nil {
			log.Logger.Fatal(err)
		}
		defer lis.Close()

		log.Logger.Fatal(g.Server.Serve(lis))
	}()

}
