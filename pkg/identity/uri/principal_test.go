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

package uri

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
			Token: &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "https://example.com/users/1"},
			Principal: principal{
				issuer: "https://accounts.example.com",
				uri:    "https://example.com/users/1",
			},
			WantErr: false,
		},
		`Issuer URL mismatch should error`: {
			Token:   &oidc.IDToken{Issuer: "https://notaccounts.example.com", Subject: "https://example.com/users/1"},
			WantErr: true,
		},
		`Subject as an email address should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "user@example.com"},
			WantErr: true,
		},
		`Incorrect subject domain hostname should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "https://notexample.com/users/1"},
			WantErr: true,
		},
		`Incorrect subject domain scheme should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "http://example.com/users/1"},
			WantErr: true,
		},
		`Invalid uri should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "not\n#a#uri"},
			WantErr: true,
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "https://example.com",
				Type:          config.IssuerTypeURI,
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
			Token:        &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "https://example.com/users/1"},
			ExpectedName: "https://example.com/users/1",
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "https://example.com",
				Type:          config.IssuerTypeURI,
			},
		},
	}
	ctx := config.With(context.Background(), cfg)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := PrincipalFromIDToken(ctx, test.Token)
			if err != nil {
				t.Fatal("didn't expect error", err)
			}

			if p.Name(ctx) != test.ExpectedName {
				t.Errorf("got %v principal name and expected %v", p.Name(ctx), test.ExpectedName)
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
		`Valid uri challenge`: {
			Principal: principal{
				issuer: `https://accounts.example.com`,
				uri:    `https://example.com/users/1`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is example.com`: factIssuerIs(`https://accounts.example.com`),
				`SAN is https://example.com/users/1`: func(cert x509.Certificate) error {
					WantURI, err := url.Parse("https://example.com/users/1")
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
		`invalid uri fails`: {
			Principal: principal{
				issuer: `example.com`,
				uri:    "\nbadurl",
			},
			WantErr: true,
		},
		`Empty issuer url should fail to render extensions`: {
			Principal: principal{
				issuer: "",
				uri:    "https://example.com/foo/bar",
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
