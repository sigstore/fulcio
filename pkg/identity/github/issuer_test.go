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

package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestIssuerMatch(t *testing.T) {
	tests := map[string]struct {
		URL         string
		ShouldMatch bool
	}{
		"Issuer should match tokens from https://token.actions.githubusercontent.com": {
			URL:         "https://token.actions.githubusercontent.com",
			ShouldMatch: true,
		},
		"Issuer shouldn't match other example.com": {
			URL:         "https://example.com",
			ShouldMatch: false,
		},
	}

	issuer, err := NewActionsIssuer("not-a-real-client-id")
	if err != nil {
		t.Fatal("Failed to even create issuer")
	}
	ctx := context.TODO()

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := issuer.Match(ctx, test.URL)
			if got != test.ShouldMatch {
				t.Error(name)
			}
		})
	}
}

type testKeySet struct {
}

func (t *testKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	// Doesn't actually verify the token, just returns the payload
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: must have 3 parts")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

func TestIssuerAuthentication(t *testing.T) {
	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal workflowPrincipal
		WantErr         bool
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sha":              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			ExpectPrincipal: workflowPrincipal{
				url:        "https://github.com/sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				sha:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				trigger:    "push",
				repository: "sigstore/fulcio",
				workflow:   "foo",
				ref:        "refs/heads/main",
			},
			WantErr: false,
		},
		`Bad audience should return error`: {
			Claims: map[string]interface{}{
				"aud":              "sigbad",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sha":              "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			WantErr: true,
		},
		`Token missing job_workflow_ref claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":        "sigstore",
				"event_name": "push",
				"exp":        0,
				"iss":        "https://token.actions.githubusercontent.com",
				"ref":        "refs/heads/main",
				"repository": "sigstore/fulcio",
				"sha":        "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":        "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":   "foo",
			},
			WantErr: true,
		},
		`Token missing sha should be rejected`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			WantErr: true,
		},
		`Token missing event_name claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sha":              "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			WantErr: true,
		},
		`Token missing repository claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"sha":              "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			WantErr: true,
		},
		`Token missing workflow claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"ref":              "refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sha":              "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
			},
			WantErr: true,
		},
		`Token missing ref claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":              "sigstore",
				"event_name":       "push",
				"exp":              0,
				"iss":              "https://token.actions.githubusercontent.com",
				"job_workflow_ref": "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"repository":       "sigstore/fulcio",
				"sha":              "bf96275471e83ff04ce5c8eb515c04a75d43f854",
				"sub":              "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":         "foo",
			},
			WantErr: true,
		},
	}

	issuer := actionsIssuer{
		IDTokenVerifier: oidc.NewVerifier(
			`https://token.actions.githubusercontent.com`,
			&testKeySet{},
			&oidc.Config{
				ClientID:        `sigstore`,
				SkipExpiryCheck: true,
			},
		)}
	ctx := context.TODO()
	signer, err := newTestSigner()
	if err != nil {
		t.Fatal("failed to make test signer")
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token, err := jwt.Signed(signer).Claims(test.Claims).CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize() = %v", err)
			}

			gotPrincipal, err := issuer.Authenticate(ctx, token)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				} else {
					return
				}
			}
			rawPrincipal, ok := gotPrincipal.(*workflowPrincipal)
			if !ok {
				t.Fatal("Wrong principal type")
			}

			if *rawPrincipal != test.ExpectPrincipal {
				t.Error(cmp.Diff(*rawPrincipal, test.ExpectPrincipal))
			}
		})
	}
}

func newTestSigner() (jose.Signer, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
	}
	return jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
}
