//
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

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/config"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestAPI(t *testing.T) {
	signer, issuer := newOIDCIssuer(t)

	subject := strings.ReplaceAll(issuer+"/foo/bar", "http", "spiffe")

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  subject,
		Audience: jwt.Audience{"sigstore"},
	}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	// Create a FulcioConfig that supports this issuer.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "spiffe"
			}
		}
	}`, issuer, issuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	// Stand up an ephemeral CA we can use for signing certificate requests.
	eca, err := ephemeralca.NewEphemeralCA()
	if err != nil {
		t.Fatalf("ephemeralca.NewEphemeralCA() = %v", err)
	}

	// Create a test HTTP server to host our API.
	h := NewHandler()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// For each request, infuse context with our snapshot of the FulcioConfig.
		ctx = config.With(ctx, cfg)

		// Decorate the context with our CA for testing.
		ctx = WithCA(ctx, eca)

		h.ServeHTTP(rw, r.WithContext(ctx))
	}))
	t.Cleanup(server.Close)

	// Create an API client that speaks to the API endpoint we created above.
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() = %v", err)
	}
	client := NewClient(u)

	// Sign the subject with our keypair, and provide the public key
	// for verification.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() = %v", err)
	}
	hash := sha256.Sum256([]byte(subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("SignASN1() = %v", err)
	}

	// Hit the API to have it sign our certificate.
	resp, err := client.SigningCert(CertificateRequest{
		PublicKey: Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}, tok)
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	// We shouldn't have an SCT because we didn't decorate context
	// with a ct-log-url
	if string(resp.SCT) != "" {
		t.Errorf("Unexpected SCT: %s", resp.SCT)
	}

	// TODO(mattmoor): What interesting checks can we perform on
	// the other return values?
}

// Stand up a very simple OIDC endpoint.
func newOIDCIssuer(t *testing.T) (jose.Signer, string) {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Cannot generate RSA key %v", err)
	}
	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}

	// Populated below, but we need to capture it first.
	var testIssuer *string

	oidcMux := http.NewServeMux()

	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for openid-configuration.")
		if err := json.NewEncoder(w).Encode(struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}{
			Issuer:  *testIssuer,
			JWKSURI: *testIssuer + "/keys",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	oidcMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for jwks.")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk.Public(),
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	oidcServer := httptest.NewServer(oidcMux)
	t.Cleanup(oidcServer.Close)

	// Setup the testIssuer, so everything uses the right URL.
	testIssuer = &oidcServer.URL

	return signer, *testIssuer
}
