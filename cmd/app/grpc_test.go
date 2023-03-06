// Copyright 2023 The Sigstore Authors.
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

package app

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/identity/base"
	"github.com/sigstore/fulcio/pkg/identity/email"
	"github.com/sigstore/fulcio/pkg/identity/github"
	"github.com/sigstore/fulcio/pkg/identity/kubernetes"
	"github.com/sigstore/fulcio/pkg/identity/spiffe"
	"github.com/sigstore/fulcio/pkg/identity/uri"
	"github.com/sigstore/fulcio/pkg/identity/username"
)

func TestIssuerPool(t *testing.T) {
	//  Test the issuer pool with the OIDCIssuers
	cfg := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{
			"https://oauth2.sigstore.dev/auth": {
				IssuerURL:   "https://oauth2.sigstore.dev/auth",
				ClientID:    "sigstore",
				IssuerClaim: "$.federated_claims.connector_id",
				Type:        config.IssuerTypeEmail,
			},
		},
	}
	// Build the expected issuer pool
	expected := identity.IssuerPool{
		email.Issuer("https://oauth2.sigstore.dev/auth"),
	}
	ignoreOpts := []cmp.Option{base.CmpOptions}
	got := NewIssuerPool(cfg)
	if d := cmp.Diff(expected, got, ignoreOpts...); d != "" {
		t.Fatal(d)
	}

	// Test the issuer pool with a MetaIssuer
	cfg = &config.FulcioConfig{
		MetaIssuers: map[string]config.OIDCIssuer{
			"https://oidc.eks.*.amazonaws.com/id/*": {
				ClientID: "bar",
				Type:     "kubernetes",
			},
		},
	}
	expected = identity.IssuerPool{
		kubernetes.Issuer("https://oidc.eks.*.amazonaws.com/id/*"),
	}
	got = NewIssuerPool(cfg)
	if d := cmp.Diff(expected, got, ignoreOpts...); d != "" {
		t.Fatal(d)
	}
}

func TestGetIssuer(t *testing.T) {
	tests := []struct {
		description string
		issuer      config.OIDCIssuer
		expected    identity.Issuer
	}{
		{
			description: "email",
			issuer: config.OIDCIssuer{
				IssuerURL: "email.com",
				Type:      "email",
			},
			expected: email.Issuer("email.com"),
		}, {
			description: "github",
			issuer: config.OIDCIssuer{
				IssuerURL: "github.com",
				Type:      "github-workflow",
			},
			expected: github.Issuer("github.com"),
		}, {
			description: "spiffe",
			issuer: config.OIDCIssuer{
				IssuerURL: "spiffe.com",
				Type:      "spiffe",
			},
			expected: spiffe.Issuer("spiffe.com"),
		}, {
			description: "kubernetes",
			issuer: config.OIDCIssuer{
				IssuerURL: "kubernetes.com",
				Type:      "kubernetes",
			},
			expected: kubernetes.Issuer("kubernetes.com"),
		}, {
			description: "uri",
			issuer: config.OIDCIssuer{
				IssuerURL: "uri.com",
				Type:      "uri",
			},
			expected: uri.Issuer("uri.com"),
		}, {
			description: "username",
			issuer: config.OIDCIssuer{
				IssuerURL: "username.com",
				Type:      "username",
			},
			expected: username.Issuer("username.com"),
		},
	}

	ignoreOpts := []cmp.Option{base.CmpOptions}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got := getIssuer("", test.issuer)
			if d := cmp.Diff(got, test.expected, ignoreOpts...); d != "" {
				t.Fatal(d)
			}
		})
	}
}
