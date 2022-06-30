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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/spf13/viper"
)

func setupHTTPServer(t *testing.T) (httpServer, string) {
	t.Helper()
	httpListen, _ := net.Listen("tcp", ":0")

	viper.Set("grpc-host", "")
	viper.Set("grpc-port", 0)
	grpcServer, err := createGRPCServer(nil, nil, &TrivialCertificateAuthority{})
	if err != nil {
		t.Error(err)
	}
	grpcServer.startTCPListener()
	// loop until server starts listening in separate goroutine
	for {
		if grpcServer.grpcServerEndpoint != ":" {
			break
		}
	}
	// set the correct listener value before creating the wrapping http server
	grpcServer.grpcServerEndpoint = strings.Replace(grpcServer.grpcServerEndpoint, "::", "localhost", 1)
	httpServer := createHTTPServer(context.Background(), httpListen.Addr().String(), grpcServer, nil)
	go func() {
		_ = httpServer.Serve(httpListen)
	}()

	return httpServer, fmt.Sprintf("http://localhost:%d", httpListen.Addr().(*net.TCPAddr).Port)

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
	if err != nil {
		t.Error(err)
		// handle error
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
	if err != nil {
		t.Error(err)
		// handle error
	}
	defer resp.Body.Close()
	fmt.Println(resp)

	for headerKey := range resp.Header {
		if strings.HasPrefix(headerKey, "Grpc-") {
			t.Errorf("found leaked Grpc response header %s", headerKey)
		}
	}
}

// Trivial CA service that returns junk
type TrivialCertificateAuthority struct {
}

func (tca *TrivialCertificateAuthority) CreateCertificate(context.Context, identity.Principal, crypto.PublicKey) (*ca.CodeSigningCertificate, error) {
	return nil, errors.New("CreateCertificate always fails for testing")
}
func (tca *TrivialCertificateAuthority) Root(ctx context.Context) ([]byte, error) {
	return []byte("not a certificate"), nil
}
