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

package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sigstore/fulcio/pkg/generated/protobuf"
)

var validYamlCfg = `
oidc-issuers:
  https://accounts.google.com:
    issuer-url: https://accounts.google.com
    client-id: foo
    type: email
    challenge-claim: email
meta-issuers:
  https://oidc.eks.*.amazonaws.com/id/*:
    client-id: bar
    type: kubernetes
  https://oidc.foo.*.bar.com/id/*:
    client-id: bar
    type: ci-provider
    ci-provider: github-workflow
`

var validJSONCfg = `
{
	"OIDCIssuers": {
		"https://accounts.google.com": {
			"IssuerURL": "https://accounts.google.com",
			"ClientID": "foo",
			"Type": "email",
			"ChallengeClaim": "email"
		}
	},
	"MetaIssuers": {
		"https://oidc.eks.*.amazonaws.com/id/*": {
			"ClientID": "bar",
			"Type": "kubernetes"
		},
		"https://oidc.foo.*.bar.com/id/*": {
			"ClientID": "bar",
			"Type": "ci-provider",
			"CiProvider": "github-workflow"
		}
	}
}
`

func TestMetaURLs(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		matches []string
		misses  []string
	}{{
		name:   "AWS meta URL",
		issuer: "https://oidc.eks.*.amazonaws.com/id/*",
		matches: []string{
			"https://oidc.eks.us-west-2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB",
		},
		misses: []string{
			// Extra dots
			"https://oidc.eks.us.west.2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB",
			// Extra slashes
			"https://oidc.eks.us-west/2.amazonaws.com/id/B02C93B6A2D3/0341AD01E1B6D48164CB",
		},
	}, {
		name:   "GKE meta URL",
		issuer: "https://container.googleapis.com/v1/projects/*/locations/*/clusters/*",
		matches: []string{
			"https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us-west1-b/clusters/tenant-cluster",
		},
		misses: []string{
			// Extra dots
			"https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us.west1.b/clusters/tenant-cluster",
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			re, err := metaRegex(test.issuer)
			if err != nil {
				t.Errorf("metaRegex() = %v", err)
			}

			for _, match := range test.matches {
				if !re.MatchString(match) {
					t.Errorf("MatchString(%q) = false, wanted true", match)
				}
			}

			for _, miss := range test.misses {
				if re.MatchString(miss) {
					t.Errorf("MatchString(%q) = true, wanted false", miss)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := map[string]struct {
		Config    *FulcioConfig
		WantError bool
	}{
		"good spiffe config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:         "issuer.example.com",
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "example.com",
					},
				},
			},
			WantError: false,
		},
		"spiffe issuer requires a trust domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeSpiffe,
					},
				},
			},
			WantError: true,
		},
		"spiffe issuer cannot be a meta issuer": {
			Config: &FulcioConfig{
				MetaIssuers: map[string]OIDCIssuer{
					"*.example.com": {
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "example.com",
					},
				},
			},
			WantError: true,
		},
		"invalid spiffe trust domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:         "issuer.example.com",
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "invalid#domain",
					},
				},
			},
			WantError: true,
		},
		"good uri config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: false,
		},
		"uri issuer requires a subject domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "https://issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeURI,
					},
				},
			},
			WantError: true,
		},
		"uri subject domain should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer url should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer and subject domains must have same top-level hostname": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://different.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer and subject domains must have same scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "http://example.com",
					},
				},
			},
			WantError: true,
		},
		"good username config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: false,
		},
		"username issuer requires a subject domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "https://issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeUsername,
					},
				},
			},
			WantError: true,
		},
		"username subject domain should not contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: true,
		},
		"username issuer url should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: true,
		},
		"username issuer and subject domains must have same top-level hostname": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "different.com",
					},
				},
			},
			WantError: true,
		},
		"non email issuer with issuer claim set is invalid": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"https://issuer.example.com": {
						IssuerURL:         "htts://issuer.example.com",
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "example.com",
						IssuerClaim:       "$.foo.bar",
					},
				},
			},
			WantError: true,
		},
		"type without challenge claim is invalid": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"https://issuer.example.com": {
						IssuerURL: "htts://issuer.example.com",
						ClientID:  "sigstore",
						Type:      "invalid",
					},
				},
			},
			WantError: true,
		},
		"nil config isn't valid": {
			Config:    nil,
			WantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateConfig(test.Config)
			if err != nil && !test.WantError {
				t.Errorf("%s: %v", name, err)
			}
			if err == nil && test.WantError {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}

func Test_isURISubjectAllowed(t *testing.T) {
	tests := []struct {
		name    string
		subject string // Parsed to url.URL
		issuer  string // Parsed to url.URL
		want    error
	}{{
		name:    "match",
		subject: "https://accounts.example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "issuer subdomain",
		subject: "https://example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "subject subdomain",
		subject: "https://profiles.example.com",
		issuer:  "https://example.com",
		want:    nil,
	}, {
		name:    "subdomain mismatch",
		subject: "https://profiles.example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "scheme mismatch",
		subject: "http://example.com",
		issuer:  "https://example.com",
		want:    fmt.Errorf("subject (http) and issuer (https) URI schemes do not match"),
	}, {
		name:    "subject domain too short",
		subject: "https://example",
		issuer:  "https://example.com",
		want:    fmt.Errorf("URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "https://example.com",
		issuer:  "https://issuer",
		want:    fmt.Errorf("URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "https://example.com",
		issuer:  "https://otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "https://example.com",
		issuer:  "https://example.org",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, example.org"),
	}}
	for _, tt := range tests {
		subject, _ := url.Parse(tt.subject)
		issuer, _ := url.Parse(tt.issuer)
		t.Run(tt.name, func(t *testing.T) {
			got := isURISubjectAllowed(subject, issuer)
			if got == nil && tt.want != nil ||
				got != nil && tt.want == nil {
				t.Errorf("isURISubjectAllowed() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Error() != tt.want.Error() {
				t.Errorf("isURISubjectAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateAllowedDomain(t *testing.T) {
	tests := []struct {
		name    string
		subject string // Parsed to url.URL
		issuer  string // Parsed to url.URL
		want    error
	}{{
		name:    "match",
		subject: "accounts.example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "issuer subdomain",
		subject: "example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "subject subdomain",
		subject: "profiles.example.com",
		issuer:  "example.com",
		want:    nil,
	}, {
		name:    "subdomain mismatch",
		subject: "profiles.example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "subject domain too short",
		subject: "example",
		issuer:  "example.com",
		want:    fmt.Errorf("URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "example.com",
		issuer:  "issuer",
		want:    fmt.Errorf("URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "example.com",
		issuer:  "otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, otherexample.com"),
	}, {
		name:    "domain mismatch, subdomain match",
		subject: "test.example.com",
		issuer:  "test.otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: test.example.com, test.otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "example.com",
		issuer:  "example.org",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, example.org"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateAllowedDomain(tt.subject, tt.issuer)
			if got == nil && tt.want != nil ||
				got != nil && tt.want == nil {
				t.Errorf("validateAllowedDomain() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Error() != tt.want.Error() {
				t.Errorf("validateAllowedDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_issuerToChallengeClaim(t *testing.T) {
	if claim := issuerToChallengeClaim(IssuerTypeEmail, ""); claim != "email" {
		t.Fatalf("expected email subject claim for email issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeSpiffe, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for SPIFFE issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeUsername, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for username issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeURI, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for URI issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeBuildkiteJob, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for Buildkite issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeGithubWorkflow, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for GitHub issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeCIProvider, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for CI issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeGitLabPipeline, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for GitLab issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeCodefreshWorkflow, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for Codefresh issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeChainguard, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for Chainguard issuer, got %s", claim)
	}
	if claim := issuerToChallengeClaim(IssuerTypeKubernetes, ""); claim != "sub" {
		t.Fatalf("expected sub subject claim for K8S issuer, got %s", claim)
	}
	// unexpected issuer has empty claim and no claim was provided
	if claim := issuerToChallengeClaim("invalid", ""); claim != "" {
		t.Fatalf("expected no claim for invalid issuer, got %s", claim)
	}
	// custom issuer provides a claim
	if claim := issuerToChallengeClaim("custom", "email"); claim != "email" {
		t.Fatalf("expected email subject claim for custom issuer, got %s", claim)
	}
}

func TestToIssuers(t *testing.T) {
	tests := []struct {
		config *FulcioConfig
		want   []*protobuf.OIDCIssuer
	}{
		{
			config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"example.com": {
						IssuerURL: "example.com",
						ClientID:  "sigstore",
						Type:      IssuerTypeEmail,
					},
				},
				MetaIssuers: map[string]OIDCIssuer{
					"wildcard.*.example.com": {
						ClientID: "sigstore",
						Type:     IssuerTypeKubernetes,
					},
				},
			},
			want: []*protobuf.OIDCIssuer{
				{
					Audience:       "sigstore",
					ChallengeClaim: "email",
					Issuer: &protobuf.OIDCIssuer_IssuerUrl{
						IssuerUrl: "example.com",
					},
					IssuerType: IssuerTypeEmail,
				},
				{
					Audience:       "sigstore",
					ChallengeClaim: "sub",
					Issuer: &protobuf.OIDCIssuer_WildcardIssuerUrl{
						WildcardIssuerUrl: "wildcard.*.example.com",
					},
					IssuerType: IssuerTypeKubernetes,
				},
			},
		},
		{
			config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"username.example.com": {
						IssuerURL:     "username.example.com",
						ClientID:      "sigstore",
						Type:          IssuerTypeUsername,
						SubjectDomain: "username.example.com",
					},
				},
			},
			want: []*protobuf.OIDCIssuer{
				{
					Audience:       "sigstore",
					ChallengeClaim: "sub",
					Issuer: &protobuf.OIDCIssuer_IssuerUrl{
						IssuerUrl: "username.example.com",
					},
					IssuerType:    IssuerTypeUsername,
					SubjectDomain: "username.example.com",
				},
			},
		},
		{
			config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"uriissuer.example.com": {
						IssuerURL:     "uriissuer.example.com",
						ClientID:      "sigstore",
						Type:          IssuerTypeURI,
						SubjectDomain: "uriissuer.example.com",
					},
				},
			},
			want: []*protobuf.OIDCIssuer{
				{
					Audience:       "sigstore",
					ChallengeClaim: "sub",
					Issuer: &protobuf.OIDCIssuer_IssuerUrl{
						IssuerUrl: "uriissuer.example.com",
					},
					IssuerType:    IssuerTypeURI,
					SubjectDomain: "uriissuer.example.com",
				},
			},
		},
	}

	for _, test := range tests {
		issuers := test.config.ToIssuers()
		if !reflect.DeepEqual(issuers, test.want) {
			t.Fatalf("expected issuers %v, got %v", test.want, issuers)
		}
	}
}

func TestVerifierCache(t *testing.T) {
	cache, err := lru.New2Q(100 /* size */)
	if err != nil {
		t.Fatal(err)
	}

	fc := &FulcioConfig{
		OIDCIssuers: map[string]OIDCIssuer{
			"issuer.dev": {
				IssuerURL: "issuer.dev",
				ClientID:  "sigstore",
			},
		},
		verifiers: map[string][]*verifierWithConfig{},
		lru:       cache,
	}

	// create a cache hit
	cfg := &oidc.Config{ClientID: "sigstore"}
	verifier := oidc.NewVerifier("issuer.dev", &mockKeySet{}, cfg)
	fc.verifiers = map[string][]*verifierWithConfig{
		"issuer.dev": {
			{
				Config:          cfg,
				IDTokenVerifier: verifier,
			},
		},
	}

	// make sure we get a hit
	v, ok := fc.GetVerifier("issuer.dev")
	if !ok {
		t.Fatal("unable to verifier")
	}
	if !reflect.DeepEqual(v, verifier) {
		t.Fatal("got unexpected verifier")
	}

	// get verifier with SkipExpiryCheck set, should fail on cache miss
	_, ok = fc.GetVerifier("issuer.dev", WithSkipExpiryCheck())
	if ok {
		t.Fatal("expected cache miss")
	}

	// create a cache hit with SkipExpiryCheck set
	withExpiryCfg := &oidc.Config{ClientID: "sigstore", SkipExpiryCheck: true}
	expiryVerifier := oidc.NewVerifier("issuer.dev", &mockKeySet{}, cfg)
	fc.verifiers = map[string][]*verifierWithConfig{
		"issuer.dev": {
			{
				Config:          cfg,
				IDTokenVerifier: verifier,
			}, {
				Config:          withExpiryCfg,
				IDTokenVerifier: expiryVerifier,
			},
		},
	}
	// make sure we get a hit and the correct verifier is returned
	v, ok = fc.GetVerifier("issuer.dev", WithSkipExpiryCheck())
	if !ok {
		t.Fatal("unable to verifier")
	}
	if !reflect.DeepEqual(v, expiryVerifier) {
		t.Fatal("got unexpected verifier")
	}
}

func TestVerifierCacheWithCustomCA(t *testing.T) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serverCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		serverCert,
		ca,
		&serverPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	serverCertPEM := new(bytes.Buffer)
	pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverKeyPEM := new(bytes.Buffer)
	pem.Encode(serverKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	serverTLSCert, err := tls.X509KeyPair(serverCertPEM.Bytes(), serverKeyPEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []interface{}{},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server.StartTLS()
	defer server.Close()

	cache, err := lru.New2Q(100)
	if err != nil {
		t.Fatal(err)
	}

	// use custom CA for OIDC issuer
	fc := &FulcioConfig{
		OIDCIssuers: map[string]OIDCIssuer{
			server.URL: {
				IssuerURL: server.URL,
				ClientID:  "sigstore",
				CACert:    caPEM.String(),
			},
		},
		verifiers: make(map[string][]*verifierWithConfig),
		lru:       cache,
	}

	verifier, ok := fc.GetVerifier(server.URL)
	if !ok {
		t.Fatal("expected to get verifier")
	}
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}

	cachedVerifier, ok := fc.GetVerifier(server.URL)
	if !ok {
		t.Fatal("expected to get cached verifier")
	}
	if !reflect.DeepEqual(verifier, cachedVerifier) {
		t.Fatal("cached verifier doesn't match original verifier")
	}

	verifierWithOptions, ok := fc.GetVerifier(server.URL, WithSkipExpiryCheck())
	if !ok {
		t.Fatal("expected to get verifier with options")
	}
	if reflect.DeepEqual(verifier, verifierWithOptions) {
		t.Fatal("verifier with options shouldn't match original verifier")
	}
}

type mockKeySet struct {
}

func (m *mockKeySet) VerifySignature(_ context.Context, _ string) (payload []byte, err error) {
	return nil, nil
}
