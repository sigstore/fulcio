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

package challenges

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestEmbedChallengeResult(t *testing.T) {
	tests := map[string]struct {
		Challenge ChallengeResult
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
			Challenge: ChallengeResult{
				Issuer:  `https://token.actions.githubusercontent.com`,
				TypeVal: GithubWorkflowValue,
				Value:   `https://github.com/foo/bar/`,
				AdditionalInfo: map[AdditionalInfo]string{
					GithubWorkflowSha:        "sha",
					GithubWorkflowTrigger:    "trigger",
					GithubWorkflowName:       "workflowname",
					GithubWorkflowRepository: "repository",
					GithubWorkflowRef:        "ref",
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
		`Email challenges should set issuer extension and email subject`: {
			Challenge: ChallengeResult{
				Issuer:  `example.com`,
				TypeVal: EmailValue,
				Value:   `alice@example.com`,
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
func Test_isSpiffeIDAllowed(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		spiffeID string
		want     bool
	}{{
		name:     "match",
		host:     "foobar.com",
		spiffeID: "spiffe://foobar.com/stuff",
		want:     true,
	}, {
		name:     "subdomain match",
		host:     "foobar.com",
		spiffeID: "spiffe://spife.foobar.com/stuff",
		want:     true,
	}, {
		name:     "subdomain mismatch",
		host:     "foo.foobar.com",
		spiffeID: "spiffe://spife.foobar.com/stuff",
		want:     false,
	}, {
		name:     "inverted mismatch",
		host:     "foo.foobar.com",
		spiffeID: "spiffe://foobar.com/stuff",
		want:     false,
	}, {
		name:     "no dot mismatch",
		host:     "foobar.com",
		spiffeID: "spiffe://foofoobar.com/stuff",
		want:     false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSpiffeIDAllowed(tt.host, tt.spiffeID); got != tt.want {
				t.Errorf("isSpiffeIDAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI(t *testing.T) {
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
	raw, ok := principal.(*ChallengeResult)
	if !ok {
		t.Fatal("expected principal to be a ChallengeResult")
	}
	if raw.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, raw.Issuer)
	}
	if raw.Value != subject {
		t.Errorf("Expected subject value %s, got %s", subject, raw.Value)
	}
	if raw.TypeVal != URIValue {
		t.Errorf("Expected type %v, got %v", URIValue, raw.TypeVal)
	}
	if raw.subject != token.Subject {
		t.Errorf("Expected subject %v, got %v", token.Subject, raw.subject)
	}
}

func TestUsername(t *testing.T) {
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
	raw, ok := principal.(*ChallengeResult)
	if !ok {
		t.Fatal("expected principal to be a ChallengeResult")
	}

	if raw.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, raw.Issuer)
	}
	if raw.Value != usernameWithEmail {
		t.Errorf("Expected subject value %s, got %s", usernameWithEmail, raw.Value)
	}
	if raw.TypeVal != UsernameValue {
		t.Errorf("Expected type %v, got %v", UsernameValue, raw.TypeVal)
	}
	if raw.subject != token.Subject {
		t.Errorf("Expected subject %s, got %s", token.Subject, raw.subject)
	}
}

func TestUsernameInvalidChar(t *testing.T) {
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

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckSignatureECDSA(t *testing.T) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	email := "test@gmail.com"
	if err := CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}

func TestCheckSignatureRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	failErr(t, err)

	email := "test@gmail.com"
	if err := CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}

func TestParsePublicKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	// succeeds with PEM-encoded key
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	failErr(t, err)
	pubKey, err := ParsePublicKey(string(pemKey))
	failErr(t, err)
	if err := cryptoutils.EqualKeys(pubKey, priv.Public()); err != nil {
		t.Fatalf("expected equal public keys")
	}

	// succeeds with DER-encoded key
	derKey, err := cryptoutils.MarshalPublicKeyToDER(priv.Public())
	failErr(t, err)
	pubKey, err = ParsePublicKey(string(derKey))
	failErr(t, err)
	if err := cryptoutils.EqualKeys(pubKey, priv.Public()); err != nil {
		t.Fatalf("expected equal public keys")
	}

	// fails with no public key
	_, err = ParsePublicKey("")
	if err == nil || err.Error() != "public key not provided" {
		t.Fatalf("expected error parsing no public key, got %v", err)
	}

	// fails with invalid public key (private key)
	pemPrivKey, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	failErr(t, err)
	_, err = ParsePublicKey(string(pemPrivKey))
	if err == nil || err.Error() != "error parsing PEM or DER encoded public key" {
		t.Fatalf("expected error parsing invalid public key, got %v", err)
	}
}
