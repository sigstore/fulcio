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

package username

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Token     *oidc.IDToken
		Principal principal
		WantErr   bool
	}{
		`Valid token authenticates with correct claims`: {
			Token: &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "alice"},
			Principal: principal{
				issuer:     "https://accounts.example.com",
				username:   "alice",
				unIdentity: "alice!example.com",
			},
			WantErr: false,
		},
		`username with ! character should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "alice!"},
			WantErr: true,
		},
		`username as an email address should error`: {
			Token:   &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "alice@example.com"},
			WantErr: true,
		},
		`invalid issuer should error`: {
			Token:   &oidc.IDToken{Issuer: "https://notaccounts.example.com", Subject: "alice"},
			WantErr: true,
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "example.com",
				Type:          config.IssuerTypeUsername,
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
			Token:        &oidc.IDToken{Issuer: "https://accounts.example.com", Subject: "alice"},
			ExpectedName: "alice",
		},
	}

	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "example.com",
				Type:          config.IssuerTypeUsername,
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
				issuer:     `https://accounts.example.com`,
				username:   "alice",
				unIdentity: "alice!example.com",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is example.com`: factIssuerIs(`https://accounts.example.com`),
				`SAN is alice!example.com`: func(cert x509.Certificate) error {
					otherName, err := cryptoutils.UnmarshalOtherNameSAN(cert.ExtraExtensions)
					if err != nil {
						return err
					}
					if len(cert.EmailAddresses) != 0 {
						return errors.New("unexpected email address SAN")
					}
					if diff := cmp.Diff(otherName, "alice!example.com"); diff != "" {
						return errors.New(diff)
					}
					return nil
				},
			},
		},
		`Empty issuer url should fail to render extensions`: {
			Principal: principal{
				issuer:     "",
				unIdentity: "alice!example.com",
				username:   "alice",
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
