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

package email

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
)

func TestPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims            map[string]interface{}
		Config            config.FulcioConfig
		ExpectedPrincipal principal
		WantErr           bool
	}{
		`Well formed token has no errors`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://iss.example.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			ExpectedPrincipal: principal{
				issuer:  "https://iss.example.com",
				address: "alice@example.com",
			},
			WantErr: false,
		},
		`Custom issuer claim`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://dex.other.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": true,
				"federated": map[string]string{
					"issuer": "https://example.com",
				},
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://dex.other.com": {
						IssuerURL:   "https://dex.other.com",
						IssuerClaim: "$.federated.issuer",
						Type:        config.IssuerTypeEmail,
						ClientID:    "sigstore",
					},
				},
			},
			ExpectedPrincipal: principal{
				issuer:  "https://example.com",
				address: "alice@example.com",
			},
			WantErr: false,
		},
		`String email verified value`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://dex.other.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": "true",
				"federated": map[string]string{
					"issuer": "https://example.com",
				},
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://dex.other.com": {
						IssuerURL:   "https://dex.other.com",
						IssuerClaim: "$.federated.issuer",
						Type:        config.IssuerTypeEmail,
						ClientID:    "sigstore",
					},
				},
			},
			ExpectedPrincipal: principal{
				issuer:  "https://example.com",
				address: "alice@example.com",
			},
			WantErr: false,
		},
		`Custom issuer claim missing`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://dex.other.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://dex.other.com": {
						IssuerURL:   "https://dex.other.com",
						IssuerClaim: "$.federated.issuer",
						Type:        config.IssuerTypeEmail,
						ClientID:    "sigstore",
					},
				},
			},
			WantErr: true,
		},
		`Email not verified should error`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://iss.example.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": false,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			WantErr: true,
		},
		`Missing email claim should error`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://iss.example.com",
				"sub":            "doesntmatter",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			WantErr: true,
		},
		`Invalid email address should error`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://iss.example.com",
				"sub":            "doesntmatter",
				"email":          "foo.com",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			WantErr: true,
		},
		`No issuer configured for token`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://nope.example.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)

			ctx := config.With(context.Background(), &test.Config)

			untyped, err := PrincipalFromIDToken(ctx, token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			gotPrincipal, ok := untyped.(principal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if gotPrincipal != test.ExpectedPrincipal {
				t.Errorf("got %v principal and expected %v", gotPrincipal, test.ExpectedPrincipal)
			}
		})
	}
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

func TestName(t *testing.T) {
	tests := map[string]struct {
		Claims       map[string]interface{}
		Config       config.FulcioConfig
		ExpectedName string
	}{
		`name should match email address`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"iss":            "https://iss.example.com",
				"sub":            "doesntmatter",
				"email":          "alice@example.com",
				"email_verified": true,
			},
			Config: config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"https://iss.example.com": {
						IssuerURL: "https://iss.example.com",
						Type:      config.IssuerTypeEmail,
						ClientID:  "sigstore",
					},
				},
			},
			ExpectedName: "alice@example.com",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)

			ctx := config.With(context.Background(), &test.Config)

			got, err := PrincipalFromIDToken(ctx, token)
			if err != nil {
				t.Fatal("didn't expect error", err)
			}

			if test.ExpectedName != got.Name(ctx) {
				t.Errorf("got %s name but expected %s", got.Name(ctx), test.ExpectedName)
			}
		})
	}

}

func TestEmbed(t *testing.T) {
	tests := map[string]struct {
		Principal principal
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`should set issuer extension and email subject`: {
			Principal: principal{
				issuer:  `https://iss.example.com`,
				address: `alice@example.com`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certificate should have alice@example.com email subject`: func(cert x509.Certificate) error {
					if len(cert.EmailAddresses) != 1 {
						return errors.New("no email SAN set for email challenge")
					}
					if cert.EmailAddresses[0] != `alice@example.com` {
						return errors.New("bad email. expected alice@example.com")
					}
					return nil
				},
				`Certificate should have issuer extension set`: factIssuerIs("https://iss.example.com"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cert x509.Certificate
			err := test.Principal.Embed(context.TODO(), &cert)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
				return
			} else if test.WantErr {
				t.Error("expected error")
			}
			for factName, fact := range test.WantFacts {
				t.Run(factName, func(t *testing.T) {
					if err := fact(cert); err != nil {
						t.Error(err)
					}
				})
			}
		})
	}
}

func factIssuerIs(issuer string) func(x509.Certificate) error {
	return factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, issuer)
}

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		for _, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(oid) {
				if !bytes.Equal(ext.Value, []byte(value)) {
					return fmt.Errorf("expected oid %v to be %s, but got %s", oid, value, ext.Value)
				}
				return nil
			}
		}
		return errors.New("extension not set")
	}
}
