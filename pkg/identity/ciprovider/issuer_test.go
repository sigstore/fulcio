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

package ciprovider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestIssuer(t *testing.T) {
	ctx := context.Background()
	url := "test-issuer-url"
	issuer := Issuer(url)

	// test the Match function
	t.Run("match", func(t *testing.T) {
		if matches := issuer.Match(ctx, url); !matches {
			t.Fatal("expected url to match but it doesn't")
		}
		if matches := issuer.Match(ctx, "some-other-url"); matches {
			t.Fatal("expected match to fail but it didn't")
		}
	})

	t.Run("authenticate", func(t *testing.T) {
		token := &oidc.IDToken{
			Issuer:  "https://iss.example.com",
			Subject: "repo:sigstore/fulcio:ref:refs/heads/main",
		}
		claims, err := json.Marshal(map[string]interface{}{
			"aud":                   "sigstore",
			"event_name":            "push",
			"exp":                   0,
			"iss":                   "https://token.actions.githubusercontent.com",
			"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
			"job_workflow_sha":      "example-sha",
			"ref":                   "refs/heads/main",
			"repository":            "sigstore/fulcio",
			"repository_id":         "12345",
			"repository_owner":      "username",
			"repository_owner_id":   "345",
			"repository_visibility": "public",
			"run_attempt":           "1",
			"run_id":                "42",
			"runner_environment":    "cloud-hosted",
			"sha":                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"sub":                   "repo:sigstore/fulcio:ref:refs/heads/main",
			"workflow":              "foo",
			"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
			"workflow_sha":          "example-sha-other",
		})
		if err != nil {
			t.Fatal(err)
		}

		withClaims(token, claims)
		ctx := context.TODO()
		OIDCIssuers :=
			map[string]config.OIDCIssuer{
				token.Issuer: {
					IssuerURL:  token.Issuer,
					Type:       config.IssuerTypeCiProvider,
					CIProvider: "github-workflow",
					ClientID:   "sigstore",
				},
			}
		cfg := &config.FulcioConfig{
			OIDCIssuers: OIDCIssuers,
		}
		ctx = config.With(ctx, cfg)
		identity.Authorize = func(_ context.Context, _ string, _ ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
			return token, nil
		}
		principal, err := issuer.Authenticate(ctx, "token")
		if err != nil {
			t.Fatal(err)
		}

		if principal.Name(ctx) != "repo:sigstore/fulcio:ref:refs/heads/main" {
			t.Fatalf("got unexpected name %s", principal.Name(ctx))
		}
	})
}
