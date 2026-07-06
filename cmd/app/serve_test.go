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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDuplex(t *testing.T) {
	// Use a custom registry to avoid conflicts with global metrics
	customRegistry := prometheus.NewRegistry()
	originalRegistry := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = customRegistry
	defer func() {
		prometheus.DefaultRegisterer = originalRegistry
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
