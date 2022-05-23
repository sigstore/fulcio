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

package spiffe

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/config"
)

func TestPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Token     *oidc.IDToken
		Principal principal
		WantErr   bool
	}{
		`Valid token authenticates with correct claims`: {
			Token: &oidc.IDToken{Issuer: "https://issuer.example.com", Subject: "spiffe://example.com/foo/bar"},
			Principal: principal{
				issuer: "https://issuer.example.com",
				id:     "spiffe://example.com/foo/bar",
			},
			WantErr: false,
		},
		`Issuer URL mismatch should error`: {
			Token:   &oidc.IDToken{Issuer: "https://foo.example.com", Subject: "spiffe://example.com/foo/bar"},
			WantErr: true,
		},
		`Incorrect trust domain should error`: {
			Token:   &oidc.IDToken{Issuer: "https://issuer.example.com", Subject: "spiffe://foo.example.com/foo/bar"},
			WantErr: true,
		},
		`Invalid ID should error`: {
			Token:   &oidc.IDToken{Issuer: "https://issuer.example.com", Subject: "not-a-spiffe-id"},
			WantErr: true,
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://issuer.example.com": {
				IssuerURL:         "https://issuer.example.com",
				ClientID:          "sigstore",
				Type:              "spiffe",
				SPIFFETrustDomain: "example.com",
			},
		},
	}
	ctx := config.With(context.Background(), cfg)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			untyped, err := PrincipalFromIDToken(ctx, test.Token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			p, ok := untyped.(principal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if p != test.Principal {
				t.Errorf("got %v principal and expected %v", p, test.Principal)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := map[string]struct {
		Token        *oidc.IDToken
		ExpectedName string
	}{
		`Valid token authenticates with correct claims`: {
			Token:        &oidc.IDToken{Issuer: "https://issuer.example.com", Subject: "spiffe://example.com/foo/bar"},
			ExpectedName: "spiffe://example.com/foo/bar",
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://issuer.example.com": {
				IssuerURL:         "https://issuer.example.com",
				ClientID:          "sigstore",
				Type:              "spiffe",
				SPIFFETrustDomain: "example.com",
			},
		},
	}
	ctx := config.With(context.Background(), cfg)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			untyped, err := PrincipalFromIDToken(ctx, test.Token)
			if err != nil {
				t.Fatal(err)
			}

			if gotName := untyped.Name(ctx); gotName != test.ExpectedName {
				t.Errorf("got %s and expected %s", gotName, test.ExpectedName)
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
		`Good spiffe challenge`: {
			Principal: principal{
				issuer: `example.com`,
				id:     `spiffe://example.com/foo/bar`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is example.com`: factIssuerIs(`example.com`),
				`SAN is spiffe://example.com/foo/bar`: func(cert x509.Certificate) error {
					WantURI, err := url.Parse("spiffe://example.com/foo/bar")
					if err != nil {
						return err
					}
					if len(cert.URIs) != 1 {
						return errors.New("no URI SAN set")
					}
					if diff := cmp.Diff(cert.URIs[0], WantURI); diff != "" {
						return errors.New(diff)
					}
					return nil
				},
			},
		},
		`Spiffe value with bad URL fails`: {
			Principal: principal{
				issuer: `example.com`,
				id:     "\nbadurl",
			},
			WantErr: true,
		},
		`Empty issuer url should fail to render extensions`: {
			Principal: principal{
				issuer: "",
				id:     "spiffe://example.com/foo/bar",
			},
			WantErr: true,
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

func TestValidSpiffeID(t *testing.T) {
	tests := map[string]struct {
		ID          string
		TrustDomain string
		WantErr     bool
	}{
		`Valid ID with matching trust domain results in no error`: {
			ID:          `spiffe://foo.com/bar`,
			TrustDomain: `foo.com`,
			WantErr:     false,
		},
		`Invalid trust domain errors`: {
			ID:          `spiffe://foo.com/bar`,
			TrustDomain: `not#a#trust#domain`,
			WantErr:     true,
		},
		`Trust domain mismatch should error`: {
			ID:          `spiffe://foo.com/bar`,
			TrustDomain: `bar.com`,
			WantErr:     true,
		},
		`Invalid spiffe id should error`: {
			ID:          `not#a#spiffe#id`,
			TrustDomain: `bar.com`,
			WantErr:     true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validSpiffeID(test.ID, test.TrustDomain)
			if err != nil {
				if !test.WantErr {
					t.Error("unepected error", err)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Error("expected err")
			}
		})
	}
}
