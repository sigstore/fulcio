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
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
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
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/server"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	LegacyUnixDomainSocket = "@fulcio-legacy-grpc-socket"
)

type grpcServer struct {
	*grpc.Server
	grpcServerEndpoint string
	caService          gw.CAServer
	tlsCertWatcher     *fsnotify.Watcher
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

type cachedTLSCert struct {
	sync.RWMutex
	certPath string
	keyPath  string
	cert     *tls.Certificate
	Watcher  *fsnotify.Watcher
}

func newCachedTLSCert(certPath, keyPath string) (*cachedTLSCert, error) {
	cachedTLSCert := &cachedTLSCert{
		certPath: certPath,
		keyPath:  keyPath,
	}
	if err := cachedTLSCert.UpdateCertificate(); err != nil {
		return nil, err
	}
	var err error
	cachedTLSCert.Watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case event, ok := <-cachedTLSCert.Watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					log.Logger.Info("fsnotify grpc-tls-certificate write event detected")
					if err := cachedTLSCert.UpdateCertificate(); err != nil {
						log.Logger.Error(err)
					}
				}
			case err, ok := <-cachedTLSCert.Watcher.Errors:
				if !ok {
					return
				}
				log.Logger.Error("fsnotify grpc-tls-certificate error:", err)
			}
		}
	}()

	// Add a path.
	if err = cachedTLSCert.Watcher.Add(certPath); err != nil {
		return nil, err
	}
	return cachedTLSCert, nil
}

func (c *cachedTLSCert) GetCertificate() *tls.Certificate {
	// get reader lock
	c.RLock()
	defer c.RUnlock()
	return c.cert
}

func (c *cachedTLSCert) UpdateCertificate() error {
	// get writer lock
	c.Lock()
	defer c.Unlock()

	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("loading GRPC tls certificate and key file: %w", err)
	}

	c.cert = &cert
	return nil
}

func (c *cachedTLSCert) GRPCCreds() grpc.ServerOption {
	return grpc.Creds(credentials.NewTLS(&tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.GetCertificate(), nil
		},
		MinVersion: tls.VersionTLS13,
	}))
}

func createGRPCServer(cfg *config.FulcioConfig, ctClient *ctclient.LogClient, baseca ca.CertificateAuthority, ip identity.IssuerPool) (*grpcServer, error) {
	logger, opts := log.SetupGRPCLogging()

	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpcmw.ChainUnaryServer(
				grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandlerContext(panicRecoveryHandler)), // recovers from per-transaction panics elegantly, so put it first
				middleware.UnaryRequestID(middleware.UseXRequestIDMetadataOption(true), middleware.XRequestMetadataLimitOption(128)),
				grpc_zap.UnaryServerInterceptor(logger, opts...),
				PassFulcioConfigThruContext(cfg),
				grpc_prometheus.UnaryServerInterceptor,
			)),
		grpc.MaxRecvMsgSize(int(maxMsgSize)),
	}

	var tlsCertWatcher *fsnotify.Watcher
	if viper.IsSet("grpc-tls-certificate") && viper.IsSet("grpc-tls-key") {
		cachedTLSCert, err := newCachedTLSCert(viper.GetString("grpc-tls-certificate"), viper.GetString("grpc-tls-key"))
		if err != nil {
			return nil, err
		}

		tlsCertWatcher = cachedTLSCert.Watcher
		serverOpts = append(serverOpts, cachedTLSCert.GRPCCreds())
	}

	myServer := grpc.NewServer(serverOpts...)

	grpcCAServer := server.NewGRPCCAServer(ctClient, baseca, ip)

	health.RegisterHealthServer(myServer, grpcCAServer)
	// Register your gRPC service implementations.
	gw.RegisterCAServer(myServer, grpcCAServer)

	grpcServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("grpc-host"), viper.GetString("grpc-port"))
	return &grpcServer{myServer, grpcServerEndpoint, grpcCAServer, tlsCertWatcher}, nil
}

func (g *grpcServer) setupPrometheus(reg *prometheus.Registry) {
	grpcMetrics := grpc_prometheus.DefaultServerMetrics
	grpcMetrics.EnableHandlingTimeHistogram()
	reg.MustRegister(grpcMetrics, server.MetricLatency, server.RequestsCount)
	grpc_prometheus.Register(g.Server)
}

func (g *grpcServer) startTCPListener(wg *sync.WaitGroup) {
	// lis is closed by g.Server.Serve() upon exit
	lis, err := net.Listen("tcp", g.grpcServerEndpoint)
	if err != nil {
		log.Logger.Fatal(err)
	}

	g.grpcServerEndpoint = lis.Addr().String()
	log.Logger.Infof("listening on grpc at %s", g.grpcServerEndpoint)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint

		// received an interrupt signal, shut down
		g.Server.GracefulStop()
		close(idleConnsClosed)
		log.Logger.Info("stopped grpc server")
	}()

	wg.Add(1)
	go func() {
		if g.tlsCertWatcher != nil {
			defer g.tlsCertWatcher.Close()
		}
		if err := g.Server.Serve(lis); err != nil {
			log.Logger.Errorf("error shutting down grpcServer: %w", err)
		}
		<-idleConnsClosed
		wg.Done()
		log.Logger.Info("grpc server shutdown")
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

func (g *grpcServer) ExposesGRPCTLS() bool {
	return viper.IsSet("grpc-tls-certificate") && viper.IsSet("grpc-tls-key")
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

	return &grpcServer{myServer, LegacyUnixDomainSocket, v2Server, nil}, nil
}

func panicRecoveryHandler(ctx context.Context, p interface{}) error {
	log.ContextLogger(ctx).Error(p)
	return fmt.Errorf("panic: %v", p)
}
