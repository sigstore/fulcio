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

func TestUri(t *testing.T) {
	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://accounts.domain.com": {
				IssuerURL:     "https://accounts.domain.com",
				ClientID:      "sigstore",
				SubjectDomain: "https://domain.com",
				Type:          config.IssuerTypeURI,
			},
		},
	}
	ctx := config.With(context.Background(), cfg)
	subjectURI := "https://domain.com/users/1"
	issuer := "https://accounts.domain.com"
	token := &oidc.IDToken{Subject: subjectURI, Issuer: issuer}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)
	h := sha256.Sum256([]byte(subjectURI))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	result, err := URI(ctx, token, priv.Public(), signature)
	if err != nil {
		t.Errorf("Expected test success, got %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, result.Issuer)
	}
	if result.Value != subjectURI {
		t.Errorf("Expected subject %s, got %s", subjectURI, result.Value)
	}
	if result.TypeVal != URIValue {
		t.Errorf("Expected type %v, got %v", URIValue, result.TypeVal)
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
		subject: "https://accounts.domain.com",
		issuer:  "https://accounts.domain.com",
		want:    nil,
	}, {
		name:    "issuer subdomain",
		subject: "https://domain.com",
		issuer:  "https://accounts.domain.com",
		want:    nil,
	}, {
		name:    "subject subdomain",
		subject: "https://profiles.domain.com",
		issuer:  "https://domain.com",
		want:    nil,
	}, {
		name:    "subdomain mismatch",
		subject: "https://profiles.domain.com",
		issuer:  "https://accounts.domain.com",
		want:    nil,
	}, {
		name:    "scheme mismatch",
		subject: "http://domain.com",
		issuer:  "https://domain.com",
		want:    fmt.Errorf("Subject (http) and Issuer (https) URI schemes do not match"),
	}, {
		name:    "subject domain too short",
		subject: "https://domain",
		issuer:  "https://domain.com",
		want:    fmt.Errorf("Subject URI hostname too short: domain"),
	}, {
		name:    "issuer domain too short",
		subject: "https://domain.com",
		issuer:  "https://issuer",
		want:    fmt.Errorf("Issuer URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "https://domain.com",
		issuer:  "https://otherdomain.com",
		want:    fmt.Errorf("Subject and issuer hostnames do not match: domain.com, otherdomain.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "https://domain.com",
		issuer:  "https://domain.org",
		want:    fmt.Errorf("Subject and issuer hostnames do not match: domain.com, domain.org"),
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
