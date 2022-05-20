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
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestEmbedChallengeResult(t *testing.T) {
	tests := map[string]struct {
		Challenge ChallengeResult
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
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
		`Good spiffe challenge`: {
			Challenge: ChallengeResult{
				Issuer:  `example.com`,
				TypeVal: SpiffeValue,
				Value:   `spiffe://example.com/foo/bar`,
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
			Challenge: ChallengeResult{
				Issuer:  `example.com`,
				TypeVal: SpiffeValue,
				Value:   "\nbadurl",
			},
			WantErr: true,
		},
		`Good Kubernetes value`: {
			Challenge: ChallengeResult{
				Issuer:  `k8s.example.com`,
				TypeVal: KubernetesValue,
				Value:   "https://k8s.example.com",
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
			Challenge: ChallengeResult{
				Issuer:  `example.com`,
				TypeVal: KubernetesValue,
				Value:   "\nbadurl",
			},
			WantErr: true,
		},
		`Good URI value`: {
			Challenge: ChallengeResult{
				Issuer:  `foo.example.com`,
				TypeVal: URIValue,
				Value:   "https://foo.example.com",
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
			Challenge: ChallengeResult{
				Issuer:  `foo.example.com`,
				TypeVal: URIValue,
				Value:   "\nnoooooo",
			},
			WantErr: true,
		},
		`Good username value`: {
			Challenge: ChallengeResult{
				Issuer:  `foo.example.com`,
				TypeVal: UsernameValue,
				Value:   "name@foo.example.com",
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
			Challenge: ChallengeResult{
				Issuer:  ``,
				TypeVal: SpiffeValue,
				Value:   "spiffe://foo.example.com/foo/bar",
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
	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"email.com": {IssuerURL: "email.com"},
		},
	}
	ctx = config.With(ctx, cfg)

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
		Config  *config.FulcioConfig
		WantErr bool
	}{
		"good token": {
			Token: &oidc.IDToken{
				Subject: "spiffe://foo.com/bar",
				Issuer:  "id.foo.com",
			},
			Config: &config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              config.IssuerTypeSpiffe,
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
			Config: &config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              config.IssuerTypeSpiffe,
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
			Config: &config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"id.bar.com": {
						IssuerURL:         "id.bar.com",
						ClientID:          "sigstore",
						Type:              config.IssuerTypeSpiffe,
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
			Config: &config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              config.IssuerTypeSpiffe,
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
			Config: &config.FulcioConfig{
				OIDCIssuers: map[string]config.OIDCIssuer{
					"id.foo.com": {
						IssuerURL:         "id.foo.com",
						ClientID:          "sigstore",
						Type:              config.IssuerTypeSpiffe,
						SPIFFETrustDomain: "foo#com",
					},
				},
			},
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := config.With(context.Background(), test.Config)
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

	// Nil key should fail
	if err := CheckSignature(nil, signature, email); err == nil {
		t.Error("nil public key should raise error")
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
