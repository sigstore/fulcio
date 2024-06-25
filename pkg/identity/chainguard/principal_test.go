// Copyright 2024 The Sigstore Authors.
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

package chainguard

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"chainguard.dev/sdk/uidp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestJobPrincipalFromIDToken(t *testing.T) {
	group := uidp.NewUIDP("")
	id := group.NewChild()

	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal workflowPrincipal
		WantErr         bool
		ErrContains     string
	}{
		`Service principal token`: {
			Claims: map[string]interface{}{
				"iss": "https://issuer.enforce.dev",
				"sub": id.String(),
				// Actor claims track the identity that was used to assume the
				// Chainguard identity.  In this case, it is the Catalog Syncer
				// service principal.
				"act": map[string]string{
					"iss": "https://iss.example.com/",
					"sub": fmt.Sprintf("catalog-syncer:%s", group.String()),
					"aud": "chainguard",
				},
				"internal": map[string]interface{}{
					"service-principal": "CATALOG_SYNCER",
				},
			},
			ExpectPrincipal: workflowPrincipal{
				issuer:  "https://issuer.enforce.dev",
				subject: id.String(),
				actor: map[string]string{
					"iss": "https://iss.example.com/",
					"sub": fmt.Sprintf("catalog-syncer:%s", group.String()),
					"aud": "chainguard",
				},
				servicePrincipal: "CATALOG_SYNCER",
			},
			WantErr: false,
		},
		`Human SSO token`: {
			Claims: map[string]interface{}{
				"iss": "https://issuer.enforce.dev",
				"sub": group.String(),
				// Actor claims track the identity that was used to assume the
				// Chainguard identity.  In this case, it is the Catalog Syncer
				// service principal.
				"act": map[string]string{
					"iss": "https://auth.chainguard.dev/",
					"sub": "google-oauth2|1234567890",
					"aud": "fdsaldfkjhasldf",
				},
			},
			ExpectPrincipal: workflowPrincipal{
				issuer:  "https://issuer.enforce.dev",
				subject: group.String(),
				actor: map[string]string{
					"iss": "https://auth.chainguard.dev/",
					"sub": "google-oauth2|1234567890",
					"aud": "fdsaldfkjhasldf",
				},
			},
			WantErr: false,
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

			untyped, err := PrincipalFromIDToken(context.TODO(), token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				if !strings.Contains(err.Error(), test.ErrContains) {
					t.Fatalf("expected error %s to contain %s", err, test.ErrContains)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			principal, ok := untyped.(*workflowPrincipal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if !reflect.DeepEqual(*principal, test.ExpectPrincipal) {
				t.Errorf("got %v principal and expected %v", *principal, test.ExpectPrincipal)
			}
		})
	}
}

func TestEmbed(t *testing.T) {
	group := uidp.NewUIDP("")
	id := group.NewChild()

	tests := map[string]struct {
		Principal identity.Principal
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Chainguard Service Principal`: {
			Principal: &workflowPrincipal{
				issuer:  "https://issuer.enforce.dev",
				subject: id.String(),
				actor: map[string]string{
					"iss": "https://iss.example.com/",
					"sub": fmt.Sprintf("catalog-syncer:%s", group.String()),
					"aud": "chainguard",
				},
				servicePrincipal: "CATALOG_SYNCER",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certificate SAN has correct value`:             factSanURIIs(fmt.Sprintf("https://issuer.enforce.dev/%s", id.String())),
				`Certificate has correct issuer (v2) extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, "https://issuer.enforce.dev"),
			},
		},
		`Chainguard Human SSO`: {
			Principal: &workflowPrincipal{
				issuer:  "https://issuer.enforce.dev",
				subject: group.String(),
				actor: map[string]string{
					"iss": "https://auth.chainguard.dev/",
					"sub": "google-oauth2|1234567890",
					"aud": "fdsaldfkjhasldf",
				},
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certificate SAN has correct value`:             factSanURIIs(fmt.Sprintf("https://issuer.enforce.dev/%s", group.String())),
				`Certificate has correct issuer (v2) extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, "https://issuer.enforce.dev"),
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

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		for _, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(oid) {
				var strVal string
				_, _ = asn1.Unmarshal(ext.Value, &strVal)
				if value != strVal {
					return fmt.Errorf("expected oid %v to be %s, but got %s", oid, value, strVal)
				}
				return nil
			}
		}
		return errors.New("extension not set")
	}
}

func factSanURIIs(value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		url, err := url.Parse(value)

		if err != nil {
			return err
		}

		if cert.URIs[0].String() != url.String() {
			return fmt.Errorf("expected SAN o be %s, but got %s", value, cert.URIs[0].String())
		}

		return nil
	}
}
