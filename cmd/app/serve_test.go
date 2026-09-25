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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/generated/protobuf"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDuplex(t *testing.T) {
	// Swap both the registerer and the gatherer so the metrics registered by
	// the duplex server are the same ones served on /metrics.
	customRegistry := prometheus.NewRegistry()
	originalRegisterer := prometheus.DefaultRegisterer
	originalGatherer := prometheus.DefaultGatherer
	prometheus.DefaultRegisterer = customRegistry
	prometheus.DefaultGatherer = customRegistry
	defer func() {
		prometheus.DefaultRegisterer = originalRegisterer
		prometheus.DefaultGatherer = originalGatherer
	}()

	// Start a server with duplex on port 8089
	ctx := context.Background()
	ca, err := ephemeralca.NewEphemeralCA()
	if err != nil {
		t.Fatal(err)
	}
	port := 8089
	serverURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	metricsPort := 2114
	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{})
	if err != nil {
		t.Error(err)
	}

	go func() {
		if err := StartDuplexServer(ctx, config.DefaultConfig, nil, ca, algorithmRegistry, "localhost", port, metricsPort, nil); err != nil {
			log.Fatalf("error starting duplex server: %v", err)
		}
	}()

	// wait for duplex server to start up
	time.Sleep(time.Second * 5)

	var rootCert string
	t.Run("http", func(t *testing.T) {
		// Make sure we can grab the rootcert with the v1 endpoint
		legacyClient := api.NewClient(serverURL)
		resp, err := legacyClient.RootCert()
		if err != nil {
			t.Fatal(err)
		}
		rootCert = string(resp.ChainPEM)
	})

	var grpcRootCert string
	t.Run("grpc", func(t *testing.T) {
		// Grab the rootcert with the v2 endpoint
		conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		grpcClient := protobuf.NewCAClient(conn)
		tb, err := grpcClient.GetTrustBundle(ctx, &protobuf.GetTrustBundleRequest{})
		if err != nil {
			t.Fatalf("error getting trust bundle: %v", err)
		}
		if len(tb.Chains) != 1 {
			t.Fatalf("didn't get expected length certificate chain: %v", tb.Chains)
		}
		if len(tb.Chains[0].Certificates) != 1 {
			t.Fatalf("didn't get expected length certs: %v", tb.Chains)
		}
		grpcRootCert = strings.TrimSuffix(tb.Chains[0].Certificates[0], "\n")
	})

	t.Run("compare root certs", func(t *testing.T) {
		if d := cmp.Diff(rootCert, grpcRootCert); d != "" {
			t.Fatal(d)
		}
	})

	t.Run("prometheus", func(t *testing.T) {
		// make sure there are metrics on the metrics port
		url := fmt.Sprintf("http://localhost:%d/metrics", metricsPort)
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		// make sure there's something about hitting the GetTrustBundle in there
		// this just confirms some metrics are being printed
		if !strings.Contains(string(contents), "GetTrustBundle") {
			t.Fatalf("didn't get expected metrics output: %s", string(contents))
		}
	})

	t.Run("healthz", func(t *testing.T) {
		url := fmt.Sprintf("http://localhost:%d/healthz", port)
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		if code := resp.StatusCode; code != 200 {
			t.Fatalf("/healthz returned status code %d, want 200", code)
		}
	})
}

func TestHostRoundTripper(t *testing.T) {
	var receivedHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := &hostRoundTripper{
		RoundTripper: http.DefaultTransport,
		host:         "custom.ct.log.origin",
	}
	client := &http.Client{Transport: rt}

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if receivedHost != "custom.ct.log.origin" {
		t.Errorf("expected host 'custom.ct.log.origin', got '%s'", receivedHost)
	}

	// Also test when inner RoundTripper is nil
	rtNil := &hostRoundTripper{
		host: "custom.ct.log.origin.nil",
	}
	clientNil := &http.Client{Transport: rtNil}

	reqNil, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	respNil, err := clientNil.Do(reqNil)
	if err != nil {
		t.Fatal(err)
	}
	respNil.Body.Close()

	if receivedHost != "custom.ct.log.origin.nil" {
		t.Errorf("expected host 'custom.ct.log.origin.nil', got '%s'", receivedHost)
	}
}

func TestServeCmdFlags(t *testing.T) {
	cmd := newServeCmd()
	f := cmd.Flags().Lookup("ct-log-origin")
	if f == nil {
		t.Fatal("expected flag ct-log-origin to exist on serve command")
	}
}

func TestResolveTLSPolicy(t *testing.T) {
	viper.Set("tls-min-version", "")
	viper.Set("tls-cipher-suites", nil)

	t.Run("defaults when unset", func(t *testing.T) {
		p, err := resolveTLSPolicy()
		if err != nil {
			t.Fatal(err)
		}
		if p.MinVersion != tls.VersionTLS13 {
			t.Errorf("minVersion = %#x, want default %#x", p.MinVersion, tls.VersionTLS13)
		}
		if p.CipherSuites != nil {
			t.Errorf("cipherSuites = %v, want nil", p.CipherSuites)
		}
	})

	t.Run("override min and ciphers", func(t *testing.T) {
		viper.Set("tls-min-version", "1.2")
		viper.Set("tls-cipher-suites", []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
		defer func() {
			viper.Set("tls-min-version", "")
			viper.Set("tls-cipher-suites", nil)
		}()
		p, err := resolveTLSPolicy()
		if err != nil {
			t.Fatal(err)
		}
		if p.MinVersion != tls.VersionTLS12 {
			t.Errorf("minVersion = %#x, want %#x", p.MinVersion, tls.VersionTLS12)
		}
		if len(p.CipherSuites) != 1 {
			t.Errorf("cipherSuites = %v, want one entry", p.CipherSuites)
		}
	})

	t.Run("invalid min version errors", func(t *testing.T) {
		viper.Set("tls-min-version", "1.1")
		defer viper.Set("tls-min-version", "")
		if _, err := resolveTLSPolicy(); err == nil {
			t.Fatal("expected error for unsupported version")
		}
	})

	t.Run("invalid cipher suite errors", func(t *testing.T) {
		viper.Set("tls-cipher-suites", []string{"NOT_A_REAL_SUITE"})
		defer viper.Set("tls-cipher-suites", nil)
		if _, err := resolveTLSPolicy(); err == nil {
			t.Fatal("expected error for unknown cipher suite")
		}
	})

	t.Run("cipher suites rejected at default TLS 1.3", func(t *testing.T) {
		viper.Set("tls-cipher-suites", []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
		defer viper.Set("tls-cipher-suites", nil)
		if _, err := resolveTLSPolicy(); err == nil {
			t.Fatal("expected error for cipher suites with TLS 1.3 minimum")
		}
	})

	t.Run("TLS 1.3-only cipher suite rejected", func(t *testing.T) {
		viper.Set("tls-min-version", "1.2")
		viper.Set("tls-cipher-suites", []string{"TLS_AES_128_GCM_SHA256"})
		defer func() {
			viper.Set("tls-min-version", "")
			viper.Set("tls-cipher-suites", nil)
		}()
		if _, err := resolveTLSPolicy(); err == nil {
			t.Fatal("expected error for TLS 1.3-only cipher suite")
		}
	})
}

// TestDuplexTLS exercises the duplex serving path with TLS enabled end to end:
// the REST endpoint must be reachable over HTTPS and a client that caps below
// the default TLS 1.3 minimum must be rejected by the server.
func TestDuplexTLS(t *testing.T) {
	// Swap the registerer and gatherer so the duplex server's metrics do not
	// collide with the default registry (matches TestDuplex).
	customRegistry := prometheus.NewRegistry()
	originalRegisterer := prometheus.DefaultRegisterer
	originalGatherer := prometheus.DefaultGatherer
	prometheus.DefaultRegisterer = customRegistry
	prometheus.DefaultGatherer = customRegistry
	defer func() {
		prometheus.DefaultRegisterer = originalRegisterer
		prometheus.DefaultGatherer = originalGatherer
	}()

	certPath, keyPath := writeTLSKeyPair(t)

	viper.Set("http-tls-certificate", certPath)
	viper.Set("http-tls-key", keyPath)
	viper.Set("tls-min-version", "")
	viper.Set("tls-cipher-suites", nil)
	defer func() {
		viper.Set("http-tls-certificate", "")
		viper.Set("http-tls-key", "")
	}()

	ca, err := ephemeralca.NewEphemeralCA()
	if err != nil {
		t.Fatal(err)
	}
	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{})
	if err != nil {
		t.Fatal(err)
	}

	const port = 8090
	const metricsPort = 2115
	go func() {
		// StartDuplexServer blocks; it is intentionally leaked for the lifetime
		// of the test binary, matching TestDuplex.
		_ = StartDuplexServer(context.Background(), config.DefaultConfig, nil, ca, algorithmRegistry, "localhost", port, metricsPort, nil)
	}()

	addr := fmt.Sprintf("localhost:%d", port)
	// Wait for the TLS listener to come up.
	var ready bool
	for i := 0; i < 50; i++ {
		conn, derr := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test client
		if derr == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("duplex TLS server did not become ready")
	}

	t.Run("https REST endpoint reachable", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test client
			},
		}
		resp, err := client.Get(fmt.Sprintf("https://%s/healthz", addr))
		if err != nil {
			t.Fatalf("HTTPS request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/healthz returned %d, want 200", resp.StatusCode)
		}
	})

	t.Run("below-minimum TLS version rejected", func(t *testing.T) {
		// Cap the client at TLS 1.2; the server's default 1.3 minimum must reject it.
		_, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- test client
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		})
		if err == nil {
			t.Fatal("expected handshake to fail for TLS < 1.3")
		}
	})
}

// writeTLSKeyPair writes the shared test certificate and key to a temp dir and
// returns their paths.
func writeTLSKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestCreateHTTPServerTLS verifies that supplying the http-tls flags configures
// the HTTP server to terminate TLS with the resolved policy (default 1.3
// minimum).
func TestCreateHTTPServerTLS(t *testing.T) {
	certPath, keyPath := writeTLSKeyPair(t)

	viper.Set("grpc-host", "")
	viper.Set("grpc-port", 0)
	viper.Set("grpc-tls-certificate", certPath)
	viper.Set("grpc-tls-key", keyPath)
	viper.Set("http-tls-certificate", certPath)
	viper.Set("http-tls-key", keyPath)
	viper.Set("tls-min-version", "")
	viper.Set("tls-cipher-suites", nil)
	defer func() {
		viper.Set("http-tls-certificate", "")
		viper.Set("http-tls-key", "")
	}()

	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{})
	if err != nil {
		t.Fatal(err)
	}
	grpcServer, err := createGRPCServer(nil, nil, &TrivialCertificateAuthority{}, algorithmRegistry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if grpcServer.tlsCertWatcher != nil {
		defer grpcServer.tlsCertWatcher.Close()
	}

	srv := createHTTPServer(context.Background(), "localhost:0", grpcServer, nil)
	if srv.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be set when http-tls-* provided")
	}
	if srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want default %#x", srv.TLSConfig.MinVersion, tls.VersionTLS13)
	}
}

// TestStartListenerTLS exercises the HTTP startListener TLS path end to end: the
// server must complete a TLS 1.3 handshake and reject a client that caps below
// the default 1.3 minimum.
func TestStartListenerTLS(t *testing.T) {
	certPath, keyPath := writeTLSKeyPair(t)

	// Reserve a concrete port for ListenAndServeTLS, then release it.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	viper.Set("grpc-host", "")
	viper.Set("grpc-port", 0)
	viper.Set("grpc-tls-certificate", certPath)
	viper.Set("grpc-tls-key", keyPath)
	viper.Set("http-tls-certificate", certPath)
	viper.Set("http-tls-key", keyPath)
	viper.Set("tls-min-version", "")
	viper.Set("tls-cipher-suites", nil)
	defer func() {
		viper.Set("http-tls-certificate", "")
		viper.Set("http-tls-key", "")
	}()

	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{})
	if err != nil {
		t.Fatal(err)
	}
	grpcServer, err := createGRPCServer(nil, nil, &TrivialCertificateAuthority{}, algorithmRegistry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if grpcServer.tlsCertWatcher != nil {
		defer grpcServer.tlsCertWatcher.Close()
	}

	srv := createHTTPServer(context.Background(), addr, grpcServer, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	srv.startListener(ctx, &wg)

	// Wait for the TLS listener to come up.
	var ready bool
	for i := 0; i < 50; i++ {
		conn, derr := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test client
		if derr == nil {
			if conn.ConnectionState().Version != tls.VersionTLS13 {
				t.Errorf("negotiated version = %#x, want %#x", conn.ConnectionState().Version, tls.VersionTLS13)
			}
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("HTTPS listener did not become ready")
	}

	// A client capped at TLS 1.2 must be rejected by the 1.3 minimum.
	if _, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test client
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}); err == nil {
		t.Fatal("expected handshake to fail for TLS < 1.3")
	}

	// Cancel the context to trigger graceful shutdown and wait for the server
	// goroutine to exit, confirming it is cleaned up (no leak). Using a context
	// instead of a process-wide signal keeps the test isolated from others in
	// the same binary.
	cancel()
	wg.Wait()
}
