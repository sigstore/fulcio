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
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
)

// TO BE IMPLEMENTED. Just kept as a guide
func TestWorkflowPrincipalFromIDToken(_ *testing.T) {

}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

func TestName(t *testing.T) {
	tests := map[string]struct {
		Claims     map[string]interface{}
		ExpectName string
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   "0",
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
			},
			ExpectName: "repo:sigstore/fulcio:ref:refs/heads/main",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)
			ctx := context.TODO()
			OIDCIssuers :=
				map[string]config.OIDCIssuer{
					token.Issuer: {
						IssuerURL: token.Issuer,
						Type:      config.IssuerTypeGithubWorkflow,
						ClientID:  "sigstore",
					},
				}
			cfg := &config.FulcioConfig{
				OIDCIssuers: OIDCIssuers,
			}
			ctx = config.With(ctx, cfg)
			principal, err := WorkflowPrincipalFromIDToken(ctx, token)
			if err != nil {
				t.Fatal(err)
			}

			gotName := principal.Name(context.TODO())
			if gotName != test.ExpectName {
				t.Error("name should match sub claim")
			}
		})
	}
}

func TestEmbed(_ *testing.T) {

}
