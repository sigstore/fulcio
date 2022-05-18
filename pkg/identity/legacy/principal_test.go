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

package legacy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
)

func TestEmbedLegacyPrincipal(t *testing.T) {
	tests := map[string]struct {
		Challenge legacyPrincipal
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
			Challenge: legacyPrincipal{
				issuer:  `https://token.actions.githubusercontent.com`,
				typeVal: GithubWorkflowValue,
				value:   `https://github.com/foo/bar/`,
				additionalInfo: map[additionalInfo]string{
					githubWorkflowSha:        "sha",
					githubWorkflowTrigger:    "trigger",
					githubWorkflowName:       "workflowname",
					githubWorkflowRepository: "repository",
					githubWorkflowRef:        "ref",
				},
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`:     factIssuerIs(`https://token.actions.githubusercontent.com`),
				`Certificate has correct trigger extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, "trigger"),
				`Certificate has correct SHA extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, "sha"),
				`Certificate has correct workflow extension`:   factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, "workflowname"),
				`Certificate has correct repository extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, "repository"),
				`Certificate has correct ref extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, "ref"),
			},
		},
		`Github workflow value with bad URL fails`: {
			Challenge: legacyPrincipal{
				issuer:  `https://token.actions.githubusercontent.com`,
				typeVal: GithubWorkflowValue,
				value:   "\nbadurl",
				additionalInfo: map[additionalInfo]string{
					githubWorkflowSha:        "sha",
					githubWorkflowTrigger:    "trigger",
					githubWorkflowName:       "workflowname",
					githubWorkflowRepository: "repository",
					githubWorkflowRef:        "ref",
				},
			},
			WantErr: true,
		},
		`Email challenges should set issuer extension and email subject`: {
			Challenge: legacyPrincipal{
				issuer:  `example.com`,
				typeVal: EmailValue,
				value:   `alice@example.com`,
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
				`Certificate should have issuer extension set`: factIssuerIs("example.com"),
			},
		},
		`Good spiffe challenge`: {
			Challenge: legacyPrincipal{
				issuer:  `example.com`,
				typeVal: SpiffeValue,
				value:   `spiffe://example.com/foo/bar`,
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
			Challenge: legacyPrincipal{
				issuer:  `example.com`,
				typeVal: SpiffeValue,
				value:   "\nbadurl",
			},
			WantErr: true,
		},
		`Good Kubernetes value`: {
			Challenge: legacyPrincipal{
				issuer:  `k8s.example.com`,
				typeVal: KubernetesValue,
				value:   "https://k8s.example.com",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is k8s.example.com`: factIssuerIs(`k8s.example.com`),
				`SAN is https://k8s.example.com`: func(cert x509.Certificate) error {
					WantURI, err := url.Parse("https://k8s.example.com")
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
		`Kubernetes value with bad URL fails`: {
			Challenge: legacyPrincipal{
				issuer:  `example.com`,
				typeVal: KubernetesValue,
				value:   "\nbadurl",
			},
			WantErr: true,
		},
		`Good URI value`: {
			Challenge: legacyPrincipal{
				issuer:  `foo.example.com`,
				typeVal: URIValue,
				value:   "https://foo.example.com",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is foo.example.com`: factIssuerIs(`foo.example.com`),
				`SAN is https://foo.example.com`: func(cert x509.Certificate) error {
					WantURI, err := url.Parse("https://foo.example.com")
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
		`Bad URI value fails`: {
			Challenge: legacyPrincipal{
				issuer:  `foo.example.com`,
				typeVal: URIValue,
				value:   "\nnoooooo",
			},
			WantErr: true,
		},
		`Good username value`: {
			Challenge: legacyPrincipal{
				issuer:  `foo.example.com`,
				typeVal: UsernameValue,
				value:   "name@foo.example.com",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Issuer	is foo.example.com`: factIssuerIs(`foo.example.com`),
				`SAN is name@foo.example.com`: func(cert x509.Certificate) error {
					if len(cert.EmailAddresses) != 1 {
						return errors.New("no email SAN set")
					}
					if cert.EmailAddresses[0] != "name@foo.example.com" {
						return errors.New("wrong email")
					}
					return nil
				},
			},
		},
		`No issuer should fail to render extensions`: {
			Challenge: legacyPrincipal{
				issuer:  ``,
				typeVal: SpiffeValue,
				value:   "spiffe://foo.example.com/foo/bar",
			},
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cert x509.Certificate
			err := test.Challenge.Embed(context.TODO(), &cert)
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

func TestURI(t *testing.T) {
	cfg := &legacyIssuer{
		OIDCIssuers: map[string]OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "https://example.com",
				Type:          issuerTypeURI,
			},
		},
	}
	ctx := with(context.Background(), cfg)
	subject := "https://example.com/users/1"
	issuer := "https://accounts.example.com"
	token := &oidc.IDToken{Subject: subject, Issuer: issuer}

	principal, err := uri(ctx, token)
	if err != nil {
		t.Errorf("Expected test success, got %v", err)
	}
	if principal.Name(ctx) != token.Subject {
		t.Errorf("Expected subject %v, got %v", token.Subject, principal.Name(ctx))
	}
	raw, ok := principal.(*legacyPrincipal)
	if !ok {
		t.Fatal("expected principal to be a legacyPrincipal")
	}
	if raw.issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, raw.issuer)
	}
	if raw.value != subject {
		t.Errorf("Expected subject value %s, got %s", subject, raw.value)
	}
	if raw.typeVal != URIValue {
		t.Errorf("Expected type %v, got %v", URIValue, raw.typeVal)
	}
	if raw.subject != token.Subject {
		t.Errorf("Expected subject %v, got %v", token.Subject, raw.subject)
	}
}

func TestUsername(t *testing.T) {
	cfg := &legacyIssuer{
		OIDCIssuers: map[string]OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "example.com",
				Type:          issuerTypeUsername,
			},
		},
	}
	ctx := with(context.Background(), cfg)
	usernameVal := "foobar"
	usernameWithEmail := "foobar@example.com"
	issuer := "https://accounts.example.com"
	token := &oidc.IDToken{Subject: usernameVal, Issuer: issuer}

	principal, err := username(ctx, token)
	if err != nil {
		t.Errorf("Expected test success, got %v", err)
	}
	if principal.Name(ctx) != token.Subject {
		t.Errorf("Expected subject %s, got %s", token.Subject, principal.Name(ctx))
	}
	raw, ok := principal.(*legacyPrincipal)
	if !ok {
		t.Fatal("expected principal to be a legacyPrincipal")
	}

	if raw.issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, raw.issuer)
	}
	if raw.value != usernameWithEmail {
		t.Errorf("Expected subject value %s, got %s", usernameWithEmail, raw.value)
	}
	if raw.typeVal != UsernameValue {
		t.Errorf("Expected type %v, got %v", UsernameValue, raw.typeVal)
	}
	if raw.subject != token.Subject {
		t.Errorf("Expected subject %s, got %s", token.Subject, raw.subject)
	}
}

func TestUsernameInvalidChar(t *testing.T) {
	cfg := &legacyIssuer{
		OIDCIssuers: map[string]OIDCIssuer{
			"https://accounts.example.com": {
				IssuerURL:     "https://accounts.example.com",
				ClientID:      "sigstore",
				SubjectDomain: "example.com",
				Type:          issuerTypeUsername,
			},
		},
	}
	ctx := with(context.Background(), cfg)
	usernameVal := "foobar@example.com"
	issuer := "https://accounts.example.com"
	token := &oidc.IDToken{Subject: usernameVal, Issuer: issuer}

	_, err := username(ctx, token)
	if err == nil {
		t.Errorf("expected test failure, got no error")
	}
	msg := "username cannot contain @ character"
	if err.Error() != msg {
		t.Errorf("unexpected test failure message, got %s, expected %s", err.Error(), msg)
	}
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func updateIDToken(idToken *oidc.IDToken, fieldName string, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(idToken))
	member := val.FieldByName(fieldName)
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

func TestEmailWithClaims(t *testing.T) {
	tests := map[string]struct {
		InputClaims []byte
		WantErr     bool
	}{
		"Good": {
			InputClaims: []byte(`{"email":"John.Doe@email.com", "email_verified":true}`),
			WantErr:     false,
		},
		"Email not verified": {
			InputClaims: []byte(`{"email":"John.Doe@email.com", "email_verified":false}`),
			WantErr:     true,
		},
		"Email missing": {
			InputClaims: []byte(`{"email_verified":true}`),
			WantErr:     true,
		},
	}

	ctx := context.Background()
	cfg := &legacyIssuer{
		OIDCIssuers: map[string]OIDCIssuer{
			"email.com": {IssuerURL: "email.com"},
		},
	}
	ctx = with(ctx, cfg)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			idToken := &oidc.IDToken{
				Issuer: `email.com`,
			}
			updateIDToken(idToken, "claims", test.InputClaims)
			_, err := email(ctx, idToken)
			if err != nil {
				if !test.WantErr {
					t.Errorf("%s: %v", name, err)
				}
				return
			} else if test.WantErr {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}

func TestSpiffe(t *testing.T) {
	tests := map[string]struct {
		Token   *oidc.IDToken
		Config  *legacyIssuer
		WantErr bool
	}{
		"good token": {
			Token: &oidc.IDToken{
				Subject: "spiffe://foo.com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &legacyIssuer{
				OIDCIssuers: map[string]OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              issuerTypeSpiffe,
						SPIFFETrustDomain: "foo.com",
					},
				},
			},
			WantErr: false,
		},
		"spiffe id wrong trust domain": {
			Token: &oidc.IDToken{
				Subject: "spiffe://baz.com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &legacyIssuer{
				OIDCIssuers: map[string]OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              issuerTypeSpiffe,
						SPIFFETrustDomain: "foo.com",
					},
				},
			},
			WantErr: true,
		},
		"spiffe id no issuer configured": {
			Token: &oidc.IDToken{
				Subject: "spiffe://foo.com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &legacyIssuer{
				OIDCIssuers: map[string]OIDCIssuer{
					"id.bar.com": {
						IssuerURL:         "id.bar.com",
						ClientID:          "sigstore",
						Type:              issuerTypeSpiffe,
						SPIFFETrustDomain: "foo.com",
					},
				},
			},
			WantErr: true,
		},
		"invalid spiffe id": {
			Token: &oidc.IDToken{
				Subject: "spiffe://foo#com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &legacyIssuer{
				OIDCIssuers: map[string]OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              issuerTypeSpiffe,
						SPIFFETrustDomain: "foo.com",
					},
				},
			},
			WantErr: true,
		},
		"invalid configured trust domain": {
			Token: &oidc.IDToken{
				Subject: "spiffe://foo.com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &legacyIssuer{
				OIDCIssuers: map[string]OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              issuerTypeSpiffe,
						SPIFFETrustDomain: "foo#com",
					},
				},
			},
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := with(context.Background(), test.Config)
			_, err := spiffe(ctx, test.Token)
			if err != nil && !test.WantErr {
				t.Errorf("%s: %v", name, err)
			}
			if err == nil && test.WantErr {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}
