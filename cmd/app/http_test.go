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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/spf13/viper"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func setupHTTPServer(t *testing.T) (httpServer, string) {
	t.Helper()
	httpListen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Error(err)
	}

	viper.Set("grpc-host", "")
	viper.Set("grpc-port", 0)
	grpcServer, err := createGRPCServer(nil, nil, &TrivialCertificateAuthority{}, nil)
	if err != nil {
		t.Error(err)
	}
	var wg sync.WaitGroup
	grpcServer.startTCPListener(&wg)
	conn, err := grpc.NewClient(grpcServer.grpcServerEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err != nil {
		t.Error(err)
	}

	httpHost := httpListen.Addr().String()
	httpServer := createHTTPServer(context.Background(), httpHost, grpcServer, nil)
	go func() {
		_ = httpServer.Serve(httpListen)
		grpcServer.GracefulStop()
	}()

	return httpServer, fmt.Sprintf("http://%s", httpHost)

}

// setup with GRPC TLS enabled
func setupHTTPServerWithGRPCTLS(t *testing.T) (httpServer, string) {
	t.Helper()
	httpListen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Error(err)
	}

	tlsPKIDir := t.TempDir()
	certPath := filepath.Join(tlsPKIDir, "cert.pem")
	os.WriteFile(certPath, []byte(certPEM), 0644)
	keyPath := filepath.Join(tlsPKIDir, "key.pem")
	os.WriteFile(keyPath, []byte(keyPEM), 0644)

	viper.Set("grpc-tls-certificate", certPath)
	viper.Set("grpc-tls-key", keyPath)

	viper.Set("grpc-host", "")
	viper.Set("grpc-port", 0)
	grpcServer, err := createGRPCServer(nil, nil, &TrivialCertificateAuthority{}, nil)
	if err != nil {
		t.Error(err)
	}

	var wg sync.WaitGroup
	grpcServer.startTCPListener(&wg)
	conn, err := grpc.NewClient(grpcServer.grpcServerEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err != nil {
		t.Error(err)
	}
	legacyGRPCServer, err := createLegacyGRPCServer(nil, LegacyUnixDomainSocket, grpcServer.caService)
	if err != nil {
		t.Fatal(err)
	}
	legacyGRPCServer.startUnixListener()

	httpHost := httpListen.Addr().String()
	httpServer := createHTTPServer(context.Background(), httpHost, grpcServer, legacyGRPCServer)
	go func() {
		_ = httpServer.Serve(httpListen)
		grpcServer.GracefulStop()
	}()

	return httpServer, fmt.Sprintf("http://%s", httpHost)

}

func TestHTTPCORSSupport(t *testing.T) {
	httpServer, host := setupHTTPServer(t)
	defer httpServer.Close()

	url, _ := url.Parse(host + "/api/v2/trustBundle")
	req := http.Request{
		Method: "GET",
		URL:    url,
		Header: map[string][]string{"Origin": {"http://example.com"}},
	}

	resp, err := http.DefaultClient.Do(&req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Errorf("missing CORS header")
	}
}

func TestHTTPDoesntLeakGRPCHeaders(t *testing.T) {
	httpServer, host := setupHTTPServer(t)
	defer httpServer.Close()

	resp, err := http.Get(host + "/api/v2/trustBundle")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error(err)
	}
	defer resp.Body.Close()

	for headerKey := range resp.Header {
		if strings.HasPrefix(headerKey, "Grpc-") {
			t.Errorf("found leaked Grpc response header %s", headerKey)
		}
	}
}

func TestIssue1267(t *testing.T) {
	httpServer, host := setupHTTPServerWithGRPCTLS(t)
	defer httpServer.Close()

	url, _ := url.Parse(host + "/api/v1/rootCert")
	req := http.Request{
		Method: "GET",
		URL:    url,
	}

	resp, err := http.DefaultClient.Do(&req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected response: %v, %v", resp, err)
	}
	defer resp.Body.Close()
}

// Trivial CA service that returns junk
type TrivialCertificateAuthority struct {
}

func (tca *TrivialCertificateAuthority) CreateCertificate(context.Context, identity.Principal, crypto.PublicKey) (*ca.CodeSigningCertificate, error) {
	return nil, errors.New("CreateCertificate always fails for testing")
}
func (tca *TrivialCertificateAuthority) TrustBundle(_ context.Context) ([][]*x509.Certificate, error) {
	return [][]*x509.Certificate{}, nil
}

func (tca *TrivialCertificateAuthority) Close() error {
	return nil
}
