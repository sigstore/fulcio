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

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	expectedNoRootMessage      = "rpc error: code = Internal desc = error communicating with CA backend"
	expectedTrustBundleMessage = "rpc error: code = Internal desc = error retrieving trust bundle from CA backend"
	bufSize                    = 1024 * 1024
)

var lis *bufconn.Listener

func passFulcioConfigThruContext(cfg *config.FulcioConfig) grpc.UnaryServerInterceptor {
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

func setupGRPCForTest(ctx context.Context, t *testing.T, cfg *config.FulcioConfig, ctl *ctclient.LogClient, ca ca.CertificateAuthority) (*grpc.Server, *grpc.ClientConn) {
	t.Helper()
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer(grpc.UnaryInterceptor(passFulcioConfigThruContext(cfg)))
	ip := NewIssuerPool(cfg)
	protobuf.RegisterCAServer(s, NewGRPCCAServer(ctl, ca, ip))
	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal("could not create grpc connection", err)
	}

	return s, conn
}

func bufDialer(ctx context.Context, _ string) (net.Conn, error) {
	return lis.DialContext(ctx)
}

func TestMissingGetTrustBundleFails(t *testing.T) {
	ctx := context.Background()
	cfg := &config.FulcioConfig{}
	server, conn := setupGRPCForTest(ctx, t, cfg, nil, &FailingCertificateAuthority{})
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	// Check that we get the CA root back as well.
	_, err := client.GetTrustBundle(ctx, &protobuf.GetTrustBundleRequest{})
	if err == nil {
		t.Fatal("GetTrustBundle did not fail", err)
	}
	if err.Error() != expectedTrustBundleMessage {
		t.Errorf("got an unexpected error: %q wanted: %q", err, expectedTrustBundleMessage)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

func TestGetTrustBundleSuccess(t *testing.T) {
	cfg := &config.FulcioConfig{}
	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	root, err := client.GetTrustBundle(ctx, &protobuf.GetTrustBundleRequest{})
	if err != nil {
		t.Fatal("GetTrustBundle failed", err)
	}
	if len(root.Chains) == 0 {
		t.Fatal("got back empty chain")
	}
	if len(root.Chains) != 1 {
		t.Fatal("got back more than one chain")
	}
	if len(root.Chains[0].Certificates) != 1 {
		t.Fatalf("expected 1 cert, found %d", len(root.Chains[0].Certificates))
	}
	block, rest := pem.Decode([]byte(root.Chains[0].Certificates[0]))
	if block == nil {
		t.Fatal("did not find PEM data")
	}
	if len(rest) != 0 {
		t.Fatal("got more than bargained for, should only have one cert")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("unexpected root type, expected CERTIFICATE, got %s", block.Type)
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse the received root cert: %v", err)
	}
	certs, _ := eca.GetSignerWithChain()
	if !rootCert.Equal(certs[0]) {
		t.Errorf("root CA does not match, wanted %+v got %+v", certs[0], rootCert)
	}
}

// Tests GetConfiguration API
func TestGetConfiguration(t *testing.T) {
	_, emailIssuer := newOIDCIssuer(t)
	_, spiffeIssuer := newOIDCIssuer(t)
	_, uriIssuer := newOIDCIssuer(t)
	_, usernameIssuer := newOIDCIssuer(t)
	_, k8sIssuer := newOIDCIssuer(t)
	_, buildkiteIssuer := newOIDCIssuer(t)
	_, gitHubIssuer := newOIDCIssuer(t)

	issuerDomain, err := url.Parse(usernameIssuer)
	if err != nil {
		t.Fatal("issuer URL could not be parsed", err)
	}

	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "spiffe",
				"SPIFFETrustDomain": "example.com"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"SubjectDomain": %q,
				"Type": "uri"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"SubjectDomain": %q,
				"Type": "username"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "buildkite-job"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "github-workflow"
			}
		},
		"MetaIssuers": {
			%q: {
				"ClientID": "sigstore",
				"Type": "kubernetes"
			}
		}
	}`, spiffeIssuer, spiffeIssuer,
		uriIssuer, uriIssuer, uriIssuer,
		emailIssuer, emailIssuer,
		usernameIssuer, usernameIssuer, issuerDomain.Hostname(),
		buildkiteIssuer, buildkiteIssuer,
		gitHubIssuer, gitHubIssuer,
		k8sIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	config, err := client.GetConfiguration(ctx, &protobuf.GetConfigurationRequest{})
	if err != nil {
		t.Fatal("GetConfiguration failed", err)
	}

	if len(config.Issuers) != 7 {
		t.Fatalf("expected 7 issuers, got %v", len(config.Issuers))
	}

	expectedIssuers := map[string]bool{
		emailIssuer: true, spiffeIssuer: true, uriIssuer: true,
		usernameIssuer: true, k8sIssuer: true, gitHubIssuer: true,
		buildkiteIssuer: true,
	}
	for _, iss := range config.Issuers {
		var issURL string
		switch {
		case expectedIssuers[iss.GetIssuerUrl()]:
			delete(expectedIssuers, iss.GetIssuerUrl())
			issURL = iss.GetIssuerUrl()
		case expectedIssuers[iss.GetWildcardIssuerUrl()]:
			delete(expectedIssuers, iss.GetWildcardIssuerUrl())
			issURL = iss.GetWildcardIssuerUrl()
		default:
			t.Fatal("issuer missing from expected issuers")
		}

		if iss.Audience != "sigstore" {
			t.Fatalf("expected audience to be sigstore, got %v", iss.Audience)
		}

		if issURL == emailIssuer {
			if iss.ChallengeClaim != "email" {
				t.Fatalf("expected email claim for email PoP challenge, got %v", iss.ChallengeClaim)
			}
		} else {
			if iss.ChallengeClaim != "sub" {
				t.Fatalf("expected sub claim for non-email PoP challenge, got %v", iss.ChallengeClaim)
			}
		}

		if issURL == spiffeIssuer {
			if iss.SpiffeTrustDomain != "example.com" {
				t.Fatalf("expected SPIFFE trust domain example.com, got %v", iss.SpiffeTrustDomain)
			}
		} else {
			if iss.SpiffeTrustDomain != "" {
				t.Fatalf("expected no SPIFFE trust domain, got %v", iss.SpiffeTrustDomain)
			}
		}
	}

	if len(expectedIssuers) != 0 {
		t.Fatal("not all issuers were found in configuration")
	}
}

// oidcTestContainer holds values needed for each API test invocation
type oidcTestContainer struct {
	Signer          jose.Signer
	Issuer          string
	Subject         string
	ExpectedSubject string
}

// customClaims holds additional JWT claims for email-based OIDC tokens
type customClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	OtherIssuer   string `json:"other_issuer"`
}

// Tests API for email subject types
func TestAPIWithEmail(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	tests := []oidcTestContainer{
		{
			Signer: emailSigner, Issuer: emailIssuer, Subject: emailSubject, ExpectedSubject: emailSubject,
		},
	}
	for _, c := range tests {
		// Create an OIDC token using this issuer's signer.
		tok, err := jwt.Signed(c.Signer).Claims(jwt.Claims{
			Issuer:   c.Issuer,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			Subject:  c.Subject,
			Audience: jwt.Audience{"sigstore"},
		}).Claims(customClaims{Email: c.Subject, EmailVerified: true}).CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize() = %v", err)
		}

		ctClient, eca := createCA(cfg, t)
		ctx := context.Background()
		server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
		defer func() {
			server.Stop()
			conn.Close()
		}()

		client := protobuf.NewCAClient(conn)

		pubBytes, proof := generateKeyAndProof(c.Subject, t)

		// Hit the API to have it sign our certificate.
		resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
			Credentials: &protobuf.Credentials{
				Credentials: &protobuf.Credentials_OidcIdentityToken{
					OidcIdentityToken: tok,
				},
			},
			Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
				PublicKeyRequest: &protobuf.PublicKeyRequest{
					PublicKey: &protobuf.PublicKey{
						Content: pubBytes,
					},
					ProofOfPossession: proof,
				},
			},
		})
		if err != nil {
			t.Fatalf("SigningCert() = %v", err)
		}

		leafCert := verifyResponse(resp, eca, c.Issuer, t)

		// Expect email subject
		if len(leafCert.EmailAddresses) != 1 {
			t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
		}
		if leafCert.EmailAddresses[0] != c.ExpectedSubject {
			t.Fatalf("subjects do not match: Expected %v, got %v", c.ExpectedSubject, leafCert.EmailAddresses[0])
		}
	}
}

// Tests API for username subject types
func TestAPIWithUsername(t *testing.T) {
	usernameSigner, usernameIssuer := newOIDCIssuer(t)

	issuerDomain, err := url.Parse(usernameIssuer)
	if err != nil {
		t.Fatal("issuer URL could not be parsed", err)
	}

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"SubjectDomain": %q,
				"Type": "username"
			}
		}
	}`, usernameIssuer, usernameIssuer, issuerDomain.Hostname())))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	usernameSubject := "foo"
	expectedUsernamedSubject := fmt.Sprintf("%s!%s", usernameSubject, issuerDomain.Hostname())

	tests := []oidcTestContainer{
		{
			Signer: usernameSigner, Issuer: usernameIssuer, Subject: usernameSubject, ExpectedSubject: expectedUsernamedSubject,
		},
	}
	for _, c := range tests {
		// Create an OIDC token using this issuer's signer.
		tok, err := jwt.Signed(c.Signer).Claims(jwt.Claims{
			Issuer:   c.Issuer,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			Subject:  c.Subject,
			Audience: jwt.Audience{"sigstore"},
		}).Claims(customClaims{Email: c.Subject, EmailVerified: true}).CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize() = %v", err)
		}

		ctClient, eca := createCA(cfg, t)
		ctx := context.Background()
		server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
		defer func() {
			server.Stop()
			conn.Close()
		}()

		client := protobuf.NewCAClient(conn)

		pubBytes, proof := generateKeyAndProof(c.Subject, t)

		// Hit the API to have it sign our certificate.
		resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
			Credentials: &protobuf.Credentials{
				Credentials: &protobuf.Credentials_OidcIdentityToken{
					OidcIdentityToken: tok,
				},
			},
			Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
				PublicKeyRequest: &protobuf.PublicKeyRequest{
					PublicKey: &protobuf.PublicKey{
						Content: pubBytes,
					},
					ProofOfPossession: proof,
				},
			},
		})
		if err != nil {
			t.Fatalf("SigningCert() = %v", err)
		}

		leafCert := verifyResponse(resp, eca, c.Issuer, t)

		// Expect no email subject
		if len(leafCert.EmailAddresses) != 0 {
			t.Fatalf("unexpected length of leaf certificate URIs, expected 0, got %d", len(leafCert.URIs))
		}
		otherName, err := cryptoutils.UnmarshalOtherNameSAN(leafCert.Extensions)
		if err != nil {
			t.Fatalf("error unmarshalling SANs: %v", err)
		}
		if otherName != c.ExpectedSubject {
			t.Fatalf("subjects do not match: Expected %v, got %v", c.ExpectedSubject, otherName)
		}
	}
}

// Tests API for SPIFFE and URI subject types
func TestAPIWithUriSubject(t *testing.T) {
	spiffeSigner, spiffeIssuer := newOIDCIssuer(t)
	uriSigner, uriIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "spiffe",
				"SPIFFETrustDomain": "foo.com"
			},
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"SubjectDomain": %q,
				"Type": "uri"
			}
		}
	}`, spiffeIssuer, spiffeIssuer, uriIssuer, uriIssuer, uriIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	spiffeSubject := "spiffe://foo.com/bar"
	uriSubject := uriIssuer + "/users/1"

	tests := []oidcTestContainer{
		{
			Signer: spiffeSigner, Issuer: spiffeIssuer, Subject: spiffeSubject,
		},
		{
			Signer: uriSigner, Issuer: uriIssuer, Subject: uriSubject,
		},
	}
	for _, c := range tests {
		// Create an OIDC token using this issuer's signer.
		tok, err := jwt.Signed(c.Signer).Claims(jwt.Claims{
			Issuer:   c.Issuer,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			Subject:  c.Subject,
			Audience: jwt.Audience{"sigstore"},
		}).CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize() = %v", err)
		}

		ctClient, eca := createCA(cfg, t)
		ctx := context.Background()
		server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
		defer func() {
			server.Stop()
			conn.Close()
		}()
		client := protobuf.NewCAClient(conn)

		pubBytes, proof := generateKeyAndProof(c.Subject, t)

		// Hit the API to have it sign our certificate.
		resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
			Credentials: &protobuf.Credentials{
				Credentials: &protobuf.Credentials_OidcIdentityToken{
					OidcIdentityToken: tok,
				},
			},
			Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
				PublicKeyRequest: &protobuf.PublicKeyRequest{
					PublicKey: &protobuf.PublicKey{
						Content: pubBytes,
					},
					ProofOfPossession: proof,
				},
			},
		})
		if err != nil {
			t.Fatalf("SigningCert() = %v", err)
		}

		leafCert := verifyResponse(resp, eca, c.Issuer, t)

		// Expect URI values
		if len(leafCert.URIs) != 1 {
			t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
		}
		uSubject, err := url.Parse(c.Subject)
		if err != nil {
			t.Fatalf("Failed to parse subject URI")
		}
		if *leafCert.URIs[0] != *uSubject {
			t.Fatalf("subjects do not match: Expected %v, got %v", uSubject, leafCert.URIs[0])
		}
	}
}

// k8sClaims holds the additional Kubernetes claims for the JWT
type k8sClaims struct {
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		}
	} `json:"kubernetes.io"`
}

// Tests API for Kubernetes URI subject types
func TestAPIWithKubernetes(t *testing.T) {
	k8sSigner, k8sIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
        "MetaIssuers": {
          %q: {
            "ClientID": "sigstore",
            "Type": "kubernetes"
          }
        }
	}`, k8sIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	namespace := "namespace"
	saName := "sa"
	k8sSubject := fmt.Sprintf("https://kubernetes.io/namespaces/%s/serviceaccounts/%s", namespace, saName)

	// Create an OIDC token using this issuer's signer.
	claims := k8sClaims{}
	claims.Kubernetes.Namespace = namespace
	claims.Kubernetes.ServiceAccount.Name = saName
	tok, err := jwt.Signed(k8sSigner).Claims(jwt.Claims{
		Issuer:   k8sIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  k8sSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(&claims).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	pubBytes, proof := generateKeyAndProof(k8sSubject, t)

	// Hit the API to have it sign our certificate.
	resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: pubBytes,
				},
				ProofOfPossession: proof,
			},
		},
	})
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	leafCert := verifyResponse(resp, eca, k8sIssuer, t)

	// Expect URI values
	if len(leafCert.URIs) != 1 {
		t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
	}
	uSubject, err := url.Parse(k8sSubject)
	if err != nil {
		t.Fatalf("failed to parse subject URI")
	}
	if *leafCert.URIs[0] != *uSubject {
		t.Fatalf("subjects do not match: Expected %v, got %v", uSubject, leafCert.URIs[0])
	}
}

// buildkiteClaims holds the additional JWT claims for Buildkite OIDC tokens
type buildkiteClaims struct {
	OrganizationSlug string `json:"organization_slug"`
	PipelineSlug     string `json:"pipeline_slug"`
}

// Tests API for Buildkite subject types
func TestAPIWithBuildkite(t *testing.T) {
	buildkiteSigner, buildkiteIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "buildkite-job"
			}
        }
	}`, buildkiteIssuer, buildkiteIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	claims := buildkiteClaims{
		OrganizationSlug: "acme-inc",
		PipelineSlug:     "bash-example",
	}
	buildkiteSubject := fmt.Sprintf("organization:%s:pipeline:%s:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build", claims.OrganizationSlug, claims.PipelineSlug)

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(buildkiteSigner).Claims(jwt.Claims{
		Issuer:   buildkiteIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  buildkiteSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(&claims).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	pubBytes, proof := generateKeyAndProof(buildkiteSubject, t)

	// Hit the API to have it sign our certificate.
	resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: pubBytes,
				},
				ProofOfPossession: proof,
			},
		},
	})
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	leafCert := verifyResponse(resp, eca, buildkiteIssuer, t)

	// Expect URI values
	if len(leafCert.URIs) != 1 {
		t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
	}
	buildkiteURL := fmt.Sprintf("https://buildkite.com/%s/%s", claims.OrganizationSlug, claims.PipelineSlug)
	buildkiteURI, err := url.Parse(buildkiteURL)
	if err != nil {
		t.Fatalf("failed to parse subject URI")
	}
	if *leafCert.URIs[0] != *buildkiteURI {
		t.Fatalf("URIs do not match: Expected %v, got %v", buildkiteURI, leafCert.URIs[0])
	}
}

// githubClaims holds the additional JWT claims for GitHub OIDC tokens
type githubClaims struct {
	JobWorkflowRef    string `json:"job_workflow_ref"`
	Sha               string `json:"sha"`
	EventName         string `json:"event_name"`
	Repository        string `json:"repository"`
	Workflow          string `json:"workflow"`
	Ref               string `json:"ref"`
	JobWorkflowSha    string `json:"job_workflow_sha"`
	RunnerEnvironment string `json:"runner_environment"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSha       string `json:"workflow_sha"`
	RunID             string `json:"run_id"`
	RunAttempt        string `json:"run_attempt"`
}

// Tests API for GitHub subject types
func TestAPIWithGitHub(t *testing.T) {
	githubSigner, githubIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "github-workflow"
			}
        }
	}`, githubIssuer, githubIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	claims := githubClaims{
		JobWorkflowRef:    "job/workflow/ref",
		Sha:               "sha",
		EventName:         "trigger",
		Repository:        "sigstore/fulcio",
		Workflow:          "workflow",
		Ref:               "refs/heads/main",
		JobWorkflowSha:    "example-sha",
		RunnerEnvironment: "cloud-hosted",
		RepositoryID:      "12345",
		RepositoryOwner:   "username",
		RepositoryOwnerID: "345",
		WorkflowRef:       "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
		WorkflowSha:       "example-sha-other",
		RunID:             "42",
		RunAttempt:        "1",
	}
	githubSubject := fmt.Sprintf("repo:%s:ref:%s", claims.Repository, claims.Ref)

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(githubSigner).Claims(jwt.Claims{
		Issuer:   githubIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  githubSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(&claims).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	pubBytes, proof := generateKeyAndProof(githubSubject, t)

	// Hit the API to have it sign our certificate.
	resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: pubBytes,
				},
				ProofOfPossession: proof,
			},
		},
	})
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	leafCert := verifyResponse(resp, eca, githubIssuer, t)

	// Expect URI values
	if len(leafCert.URIs) != 1 {
		t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
	}
	githubURL := fmt.Sprintf("https://github.com/%s", claims.JobWorkflowRef)
	githubURI, err := url.Parse(githubURL)
	if err != nil {
		t.Fatalf("failed to parse expected url")
	}
	if *leafCert.URIs[0] != *githubURI {
		t.Fatalf("URIs do not match: Expected %v, got %v", githubURI, leafCert.URIs[0])
	}
	// Verify custom OID values
	deprecatedExpectedExts := map[int]string{
		2: claims.EventName,
		3: claims.Sha,
		4: claims.Workflow,
		5: claims.Repository,
		6: claims.Ref,
	}
	for o, value := range deprecatedExpectedExts {
		ext, found := findCustomExtension(leafCert, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, o})
		if !found {
			t.Fatalf("expected extension in custom OID 1.3.6.1.4.1.57264.1.%d", o)
		}
		if string(ext.Value) != value {
			t.Fatalf("unexpected extension value, expected %s, got %s", value, ext.Value)
		}
	}
	url := "https://github.com/"
	expectedExts := map[int]string{
		9:  url + claims.JobWorkflowRef,
		10: claims.JobWorkflowSha,
		11: claims.RunnerEnvironment,
		12: url + claims.Repository,
		13: claims.Sha,
		14: claims.Ref,
		15: claims.RepositoryID,
		16: url + claims.RepositoryOwner,
		17: claims.RepositoryOwnerID,
		18: url + claims.WorkflowRef,
		19: claims.WorkflowSha,
		20: claims.EventName,
		21: url + claims.Repository + "/actions/runs/" + claims.RunID + "/attempts/" + claims.RunAttempt,
	}
	for o, value := range expectedExts {
		ext, found := findCustomExtension(leafCert, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, o})
		if !found {
			t.Fatalf("expected extension in custom OID 1.3.6.1.4.1.57264.1.%d", o)
		}
		var extValue string
		rest, err := asn1.Unmarshal(ext.Value, &extValue)
		if err != nil {
			t.Fatalf("error unmarshalling extension: :%v", err)
		}
		if len(rest) != 0 {
			t.Fatal("error unmarshalling extension, rest is not 0")
		}
		if string(extValue) != value {
			t.Fatalf("unexpected extension value, expected %s, got %s", value, extValue)
		}
	}
}

// Tests API with issuer claim in different field in the OIDC token
func TestAPIWithIssuerClaimConfig(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email",
				"IssuerClaim": "$.other_issuer"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"
	otherIssuerVal := "other.issuer.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true, OtherIssuer: otherIssuerVal}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	pubBytes, proof := generateKeyAndProof(emailSubject, t)

	// Hit the API to have it sign our certificate.
	resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: pubBytes,
				},
				ProofOfPossession: proof,
			},
		},
	})
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	// The issuer should be otherIssuerVal, not emailIssuer
	leafCert := verifyResponse(resp, eca, otherIssuerVal, t)

	// Expect email subject
	if len(leafCert.EmailAddresses) != 1 {
		t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
	}
	if leafCert.EmailAddresses[0] != emailSubject {
		t.Fatalf("subjects do not match: Expected %v, got %v", emailSubject, leafCert.EmailAddresses[0])
	}
}

// Tests API with challenge sent as CSR
func TestAPIWithCSRChallenge(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports this issuer.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	derCSR, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatalf("error creating CSR: %v", err)
	}
	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derCSR,
	})

	// Hit the API to have it sign our certificate.
	resp, err := client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_CertificateSigningRequest{
			CertificateSigningRequest: pemCSR,
		},
	})
	if err != nil {
		t.Fatalf("SigningCert() = %v", err)
	}

	leafCert := verifyResponse(resp, eca, emailIssuer, t)

	// Expect email subject
	if len(leafCert.EmailAddresses) != 1 {
		t.Fatalf("unexpected length of leaf certificate URIs, expected 1, got %d", len(leafCert.URIs))
	}
	if leafCert.EmailAddresses[0] != emailSubject {
		t.Fatalf("subjects do not match: Expected %v, got %v", emailSubject, leafCert.EmailAddresses[0])
	}
}

// Tests API with insecure pub key
func TestAPIWithInsecurePublicKey(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey() = %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() = %v", err)
	}

	// Hit the API to have it sign our certificate.
	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: string(cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, pubBytes)),
				},
				ProofOfPossession: []byte{},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "The public key supplied in the request is insecure") {
		t.Fatalf("expected insecure public key error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

// Tests API with no public key
func TestAPIWithoutPublicKey(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	// Test with no key proto specified
	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "The public key supplied in the request could not be parsed") {
		t.Fatalf("expected parsing public key error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}

	// Test with no public key specified
	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "The public key supplied in the request could not be parsed") {
		t.Fatalf("expected parsing public key error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

// Tests API with invalid challenge as proof of possession of private key
func TestAPIWithInvalidChallenge(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports these issuers.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	pubBytes, _ := generateKeyAndProof(emailSubject, t)
	_, invalidProof := generateKeyAndProof(emailSubject, t)

	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &protobuf.PublicKeyRequest{
				PublicKey: &protobuf.PublicKey{
					Content: pubBytes,
				},
				ProofOfPossession: invalidProof,
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "The signature supplied in the request could not be verified") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

// Tests API with an invalid CSR.
func TestAPIWithInvalidCSR(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports this issuer.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_CertificateSigningRequest{
			CertificateSigningRequest: []byte("invalid"),
		},
	})

	if err == nil || !strings.Contains(err.Error(), "The certificate signing request could not be parsed") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

// Tests API with unsigned CSR, which will fail signature verification.
func TestAPIWithInvalidCSRSignature(t *testing.T) {
	emailSigner, emailIssuer := newOIDCIssuer(t)

	// Create a FulcioConfig that supports this issuer.
	cfg, err := config.Read([]byte(fmt.Sprintf(`{
		"OIDCIssuers": {
			%q: {
				"IssuerURL": %q,
				"ClientID": "sigstore",
				"Type": "email"
			}
		}
	}`, emailIssuer, emailIssuer)))
	if err != nil {
		t.Fatalf("config.Read() = %v", err)
	}

	emailSubject := "foo@example.com"

	// Create an OIDC token using this issuer's signer.
	tok, err := jwt.Signed(emailSigner).Claims(jwt.Claims{
		Issuer:   emailIssuer,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  emailSubject,
		Audience: jwt.Audience{"sigstore"},
	}).Claims(customClaims{Email: emailSubject, EmailVerified: true}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	ctClient, eca := createCA(cfg, t)
	ctx := context.Background()
	server, conn := setupGRPCForTest(ctx, t, cfg, ctClient, eca)
	defer func() {
		server.Stop()
		conn.Close()
	}()

	client := protobuf.NewCAClient(conn)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}
	derCSR, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatalf("error creating CSR: %v", err)
	}
	// Corrupt signature
	derCSR[len(derCSR)-1] = derCSR[len(derCSR)-1] + 1
	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derCSR,
	})

	// Hit the API to have it sign our certificate.
	_, err = client.CreateSigningCertificate(ctx, &protobuf.CreateSigningCertificateRequest{
		Credentials: &protobuf.Credentials{
			Credentials: &protobuf.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok,
			},
		},
		Key: &protobuf.CreateSigningCertificateRequest_CertificateSigningRequest{
			CertificateSigningRequest: pemCSR,
		},
	})

	if err == nil || !strings.Contains(err.Error(), "The signature supplied in the request could not be verified") {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

// Stand up a very simple OIDC endpoint.
func newOIDCIssuer(t *testing.T) (jose.Signer, string) {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
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

func fakeCTLogServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		addJSONResp := `{
			"sct_version":0,
			"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=",
			"timestamp":1337,
			"extensions":"",
			"signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="
		 }`
		fmt.Fprint(w, string(addJSONResp))
	}))
}

// createCA initializes an ephemeral CA server and CT log server
func createCA(cfg *config.FulcioConfig, t *testing.T) (*ctclient.LogClient, *ephemeralca.EphemeralCA) {
	// Stand up an ephemeral CA we can use for signing certificate requests.
	eca, err := ephemeralca.NewEphemeralCA()
	if err != nil {
		t.Fatalf("ephemeralca.NewEphemeralCA() = %v", err)
	}

	ctlogServer := fakeCTLogServer(t)
	if ctlogServer == nil {
		t.Fatalf("failed to create the fake ctlog server")
	}

	// Create a test HTTP server to host our API.
	ctClient, err := ctclient.New(ctlogServer.URL,
		&http.Client{Timeout: 30 * time.Second},
		jsonclient.Options{})
	if err != nil {
		t.Fatalf("error creating CT client: %v", err)
	}
	return ctClient, eca
}

// generateKeyAndProof creates a public key to be certified and creates a
// signature for the OIDC token subject
func generateKeyAndProof(subject string, t *testing.T) (string, []byte) {
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
	return string(cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, pubBytes)), proof
}

// findCustomExtension searches a certificate's non-critical extensions by OID
func findCustomExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range cert.Extensions {
		if reflect.DeepEqual(ext.Id, oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// verifyResponse validates common response expectations for each response field
func verifyResponse(resp *protobuf.SigningCertificate, eca *ephemeralca.EphemeralCA, issuer string, t *testing.T) *x509.Certificate {
	// Expect SCT
	if resp.GetSignedCertificateDetachedSct() != nil && string(resp.GetSignedCertificateDetachedSct().SignedCertificateTimestamp) == "" {
		t.Fatal("unexpected empty SCT in response")
	}

	var chain *protobuf.CertificateChain
	if resp.GetSignedCertificateDetachedSct() != nil {
		chain = resp.GetSignedCertificateDetachedSct().Chain
	} else {
		chain = resp.GetSignedCertificateEmbeddedSct().Chain
	}

	// Expect root certficate in resp.ChainPEM
	if len(chain.Certificates) == 0 {
		t.Fatal("unexpected empty chain in response")
	}

	// Expect root cert matches the server's configured root
	block, rest := pem.Decode([]byte(chain.Certificates[1]))
	if block == nil {
		t.Fatal("missing PEM data")
	}
	// Note: This may change in the future if we use intermediate certificates.
	if len(rest) != 0 {
		t.Fatal("expected only one certificate in PEM block chain")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("unexpected root type, expected CERTIFICATE, got %s", block.Type)
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse the received root cert: %v", err)
	}
	certs, _ := eca.GetSignerWithChain()
	if !rootCert.Equal(certs[0]) {
		t.Errorf("root CA does not match, wanted %+v got %+v", certs[0], rootCert)
	}

	// Expect leaf certificate values
	// TODO: if there are intermediates added, this logic needs to change
	block, rest = pem.Decode([]byte(chain.Certificates[0]))
	if len(rest) != 0 {
		t.Fatal("expected only one leaf certificate in PEM block")
	}
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse the received leaf cert: %v", err)
	}
	if leafCert.SerialNumber == nil {
		t.Fatalf("expected certificate serial number")
	}
	if leafCert.NotAfter.Sub(leafCert.NotBefore) != time.Duration(10*time.Minute) {
		t.Fatalf("expected 10 minute lifetime, got %v", leafCert.NotAfter.Sub(leafCert.NotBefore))
	}
	if len(leafCert.SubjectKeyId) != 20 {
		t.Fatalf("expected certificate subject key ID to be of length 20 bytes, got %d", len(leafCert.SubjectKeyId))
	}
	if leafCert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("unexpected key usage, expected %v, got %v", x509.KeyUsageDigitalSignature, leafCert.KeyUsage)
	}
	if len(leafCert.ExtKeyUsage) != 1 {
		t.Fatalf("unexpected length of extended key usage, expected 1, got %d", len(leafCert.ExtKeyUsage))
	}
	if leafCert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("unexpected key usage, expected %v, got %v", x509.ExtKeyUsageCodeSigning, leafCert.ExtKeyUsage[0])
	}
	// Check issuer in custom OIDs
	issuerExt, found := findCustomExtension(leafCert, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1})
	if !found {
		t.Fatal("expected issuer in custom OID 1.3.6.1.4.1.57264.1.1")
	}
	if string(issuerExt.Value) != issuer {
		t.Fatalf("unexpected issuer for 1.1, expected %s, got %s", issuer, string(issuerExt.Value))
	}
	issuerExt, found = findCustomExtension(leafCert, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8})
	if !found {
		t.Fatal("expected issuer in custom OID 1.3.6.1.4.1.57264.1.8")
	}
	// verify ASN.1 encoding is correct
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(issuerExt.Value, &raw)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling issuer to RawValue: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes in issuer")
	}
	// Universal class
	if raw.Class != 0 {
		t.Fatalf("expected ASN.1 issuer class to be 0, got %d", raw.Class)
	}
	// UTF8String
	if raw.Tag != 12 {
		t.Fatalf("expected ASN.1 issuer tag to be 12, got %d", raw.Tag)
	}
	// verify issuer unmarshals properly
	var issuerVal string
	rest, err = asn1.Unmarshal(issuerExt.Value, &issuerVal)
	if err != nil {
		t.Fatalf("unexpected error unmarshalling issuer: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes in issuer")
	}
	if string(issuerVal) != issuer {
		t.Fatalf("unexpected issuer 1.3.6.1.4.1.57264.1.8, expected %s, got %s", issuer, string(issuerExt.Value))
	}

	return leafCert
}

// Fake CA service that always fails.
type FailingCertificateAuthority struct {
}

func (fca *FailingCertificateAuthority) CreateCertificate(context.Context, identity.Principal, crypto.PublicKey) (*ca.CodeSigningCertificate, error) {
	return nil, errors.New("CreateCertificate always fails for testing")
}
func (fca *FailingCertificateAuthority) TrustBundle(ctx context.Context) ([][]*x509.Certificate, error) {
	return nil, errors.New("TrustBundle always fails for testing")
}

func (fca *FailingCertificateAuthority) Close() error {
	return nil
}
