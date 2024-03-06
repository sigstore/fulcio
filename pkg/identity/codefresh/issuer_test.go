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

package codefresh

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
			Subject: "account:628a80b693a15c0f9c13ab75:pipeline:65e6d5551e47e5bc243ca93f:scm_repo_url:https://github.com/test-codefresh/fulcio:scm_user_name:test-codefresh:scm_ref:feat/codefresh-issuer:scm_pull_request_target_branch:main",
		}
		claims, err := json.Marshal(map[string]interface{}{
			"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e6d5551e47e5bc243ca93f:scm_repo_url:https://github.com/test-codefresh/fulcio:scm_user_name:test-codefresh:scm_ref:feat/codefresh-issuer:scm_pull_request_target_branch:main",
			"account_id": "628a80b693a15c0f9c13ab75",
			"account_name": "test-codefresh",
			"pipeline_id": "65e6d5551e47e5bc243ca93f",
			"pipeline_name": "oidc-test/oidc-test-2",
			"workflow_id": "65e6ebe0bfbfa1782876165e",
			"scm_user_name": "test-codefresh",
			"scm_repo_url": "https://github.com/test-codefresh/fulcio",
			"scm_ref": "feat/codefresh-issuer",
			"scm_pull_request_target_branch": "main",
			"runner_environment": "hybrid",
			"aud": "sigstore",
			"exp": 1709633177,
			"iat": 1709632877,
			"iss": "https://oidc.codefresh.io",
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

		if principal.Name(ctx) != "account:628a80b693a15c0f9c13ab75:pipeline:65e6d5551e47e5bc243ca93f:scm_repo_url:https://github.com/test-codefresh/fulcio:scm_user_name:test-codefresh:scm_ref:feat/codefresh-issuer:scm_pull_request_target_branch:main" {
			t.Fatalf("got unexpected name %s", principal.Name(ctx))
		}
	})
}
