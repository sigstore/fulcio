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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
)

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

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)
	h := sha256.Sum256([]byte(subject))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	result, err := URI(ctx, token, priv.Public(), signature)
	if err != nil {
		t.Errorf("Expected test success, got %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, result.Issuer)
	}
	if result.Value != subject {
		t.Errorf("Expected subject %s, got %s", subject, result.Value)
	}
	if result.TypeVal != URIValue {
		t.Errorf("Expected type %v, got %v", URIValue, result.TypeVal)
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
	username := "foobar"
	usernameWithEmail := "foobar@example.com"
	issuer := "https://accounts.example.com"
	token := &oidc.IDToken{Subject: username, Issuer: issuer}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)
	h := sha256.Sum256([]byte(username))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	result, err := Username(ctx, token, priv.Public(), signature)
	if err != nil {
		t.Errorf("Expected test success, got %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, result.Issuer)
	}
	if result.Value != usernameWithEmail {
		t.Errorf("Expected subject %s, got %s", usernameWithEmail, result.Value)
	}
	if result.TypeVal != UsernameValue {
		t.Errorf("Expected type %v, got %v", UsernameValue, result.TypeVal)
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
		want:    fmt.Errorf("subject URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "https://example.com",
		issuer:  "https://issuer",
		want:    fmt.Errorf("issuer URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "https://example.com",
		issuer:  "https://otherexample.com",
		want:    fmt.Errorf("subject and issuer hostnames do not match: example.com, otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "https://example.com",
		issuer:  "https://example.org",
		want:    fmt.Errorf("subject and issuer hostnames do not match: example.com, example.org"),
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

func Test_isDomainAllowed(t *testing.T) {
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
		want:    fmt.Errorf("subject URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "example.com",
		issuer:  "issuer",
		want:    fmt.Errorf("issuer URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "example.com",
		issuer:  "otherexample.com",
		want:    fmt.Errorf("subject and issuer hostnames do not match: example.com, otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "example.com",
		issuer:  "example.org",
		want:    fmt.Errorf("subject and issuer hostnames do not match: example.com, example.org"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDomainAllowed(tt.subject, tt.issuer)
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
