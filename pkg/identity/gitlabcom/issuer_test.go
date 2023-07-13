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

package gitlabcom

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
			"namespace_id":       "1730270",
			"namespace_path":     "cpanato",
			"project_id":         "42831435",
			"project_path":       "cpanato/testing-cosign",
			"user_id":            "1430381",
			"user_login":         "cpanato",
			"user_email":         "cpanato@example.com",
			"pipeline_id":        "757451528",
			"pipeline_source":    "push",
			"ci_config_ref_uri":  "gitlab.com/cpanto/testing-cosign//.gitlab-ci.yml@refs/head/main",
			"job_id":             "3659681386",
			"sha":                "714a629c0b401fdce83e847fc9589983fc6f46bc",
			"runner_id":          1,
			"runner_environment": "gitlab-hosted",
			"ref":                "main",
			"ref_type":           "branch",
			"ref_protected":      "true",
			"jti":                "914910cc-09f6-4217-8091-a1d3231a37db",
			"iss":                "https://gitlab.com",
			"iat":                1674658264,
			"nbf":                1674658259,
			"exp":                1674661864,
			"sub":                "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
			"aud":                "sigstore",
		})
		if err != nil {
			t.Fatal(err)
		}
		withClaims(token, claims)

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
