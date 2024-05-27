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

package generic

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestWorkflowPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal Provider
		WantErr         bool
		ErrContains     string
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
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
			},
			ExpectPrincipal: Provider{},
			WantErr:         false,
		},
		`Token missing job_workflow_ref claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
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
			WantErr:     true,
			ErrContains: "job_workflow_ref",
		},
		`Token missing sha should be rejected`: {
			Claims: map[string]interface{}{
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
				"sub":                   "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":              "foo",
				"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "sha",
		},
		`Token missing event_name claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
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
			},
			WantErr:     true,
			ErrContains: "event_name",
		},
		`Token missing repository claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
				"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"job_workflow_sha":      "example-sha",
				"ref":                   "refs/heads/main",
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
			WantErr:     true,
			ErrContains: "repository",
		},
		`Token missing workflow claim should be rejected`: {
			Claims: map[string]interface{}{
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
				"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "workflow",
		},
		`Token missing ref claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
				"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"job_workflow_sha":      "example-sha",
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
			WantErr:     true,
			ErrContains: "ref",
		},
		`Token missing job_workflow_sha claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
				"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
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
			WantErr:     true,
			ErrContains: "job_workflow_sha",
		},
		`Token missing runner_environment claim should be rejected`: {
			Claims: map[string]interface{}{
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
				"sha":                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"sub":                   "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":              "foo",
				"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "runner_environment",
		},
		`Token missing repository_id claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
				"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"job_workflow_sha":      "example-sha",
				"ref":                   "refs/heads/main",
				"repository":            "sigstore/fulcio",
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
			WantErr:     true,
			ErrContains: "repository_id",
		},
		`Token missing repository_owner claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                   "sigstore",
				"event_name":            "push",
				"exp":                   0,
				"iss":                   "https://token.actions.githubusercontent.com",
				"job_workflow_ref":      "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"job_workflow_sha":      "example-sha",
				"ref":                   "refs/heads/main",
				"repository":            "sigstore/fulcio",
				"repository_id":         "12345",
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
			WantErr:     true,
			ErrContains: "repository_owner",
		},
		`Token missing repository_owner_id claim should be rejected`: {
			Claims: map[string]interface{}{
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
			WantErr:     true,
			ErrContains: "repository_owner_id",
		},
		`Token missing workflow_ref claim should be rejected`: {
			Claims: map[string]interface{}{
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
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "workflow_ref",
		},
		`Token missing workflow_sha claim should be rejected`: {
			Claims: map[string]interface{}{
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
			},
			WantErr:     true,
			ErrContains: "workflow_sha",
		},
		`Token missing run_id claim should be rejected`: {
			Claims: map[string]interface{}{
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
				"runner_environment":    "cloud-hosted",
				"sha":                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"sub":                   "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":              "foo",
				"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "run_id",
		},
		`Token missing run_attempt claim should be rejected`: {
			Claims: map[string]interface{}{
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
				"run_id":                "42",
				"runner_environment":    "cloud-hosted",
				"sha":                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"sub":                   "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":              "foo",
				"workflow_ref":          "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":          "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "run_attempt",
		},
		`Token missing repository_visibility claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":                 "sigstore",
				"event_name":          "push",
				"exp":                 0,
				"iss":                 "https://token.actions.githubusercontent.com",
				"job_workflow_ref":    "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				"job_workflow_sha":    "example-sha",
				"ref":                 "refs/heads/main",
				"repository":          "sigstore/fulcio",
				"repository_id":       "12345",
				"repository_owner":    "username",
				"repository_owner_id": "345",
				"run_id":              "42",
				"runner_environment":  "cloud-hosted",
				"sha":                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"sub":                 "repo:sigstore/fulcio:ref:refs/heads/main",
				"workflow":            "foo",
				"workflow_ref":        "sigstore/other/.github/workflows/foo.yaml@refs/heads/main",
				"workflow_sha":        "example-sha-other",
			},
			WantErr:     true,
			ErrContains: "repository_visibility",
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

			// untyped, err := WorkflowPrincipalFromIDToken(context.TODO(), token)
			// if err != nil {
			// 	if !test.WantErr {
			// 		t.Fatal("didn't expect error", err)
			// 	}
			// 	if !strings.Contains(err.Error(), test.ErrContains) {
			// 		t.Fatalf("expected error %s to contain %s", err, test.ErrContains)
			// 	}
			// 	return
			// }
			// if err == nil && test.WantErr {
			// 	t.Fatal("expected error but got none")
			// }

			// principal, ok := untyped.(*Provider)
			// if !ok {
			// 	t.Errorf("Got wrong principal type %v", untyped)
			// }
			// if *principal != test.ExpectPrincipal {
			// 	t.Errorf("got %v principal and expected %v", *principal, test.ExpectPrincipal)
			// }
		})
	}
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

			principal, err := WorkflowPrincipalFromIDToken(context.TODO(), token)
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

func TestEmbed(t *testing.T) {
	tests := map[string]struct {
		Principal identity.Principal
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
			Principal: &Provider{},
			WantErr:   false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`:                       factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, "https://token.actions.githubusercontent.com"),
				`Certificate has correct trigger extension`:                      factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, "trigger"),
				`Certificate has correct SHA extension`:                          factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, "sha"),
				`Certificate has correct workflow extension`:                     factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, "workflowname"),
				`Certificate has correct repository extension`:                   factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, "repository"),
				`Certificate has correct ref extension`:                          factDeprecatedExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, "ref"),
				`Certificate has correct issuer (v2) extension`:                  factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, "https://token.actions.githubusercontent.com"),
				`Certificate has correct builder signer URI extension`:           factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}, "https://github.com/jobWorkflowRef"),
				`Certificate has correct builder signer digest extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}, "jobWorkflowSha"),
				`Certificate has correct runner environment extension`:           factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}, "runnerEnv"),
				`Certificate has correct source repo URI extension`:              factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}, "https://github.com/repository"),
				`Certificate has correct source repo digest extension`:           factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}, "sha"),
				`Certificate has correct source repo ref extension`:              factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}, "ref"),
				`Certificate has correct source repo ID extension`:               factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}, "repoID"),
				`Certificate has correct source repo owner URI extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16}, "https://github.com/repoOwner"),
				`Certificate has correct source repo owner ID extension`:         factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}, "repoOwnerID"),
				`Certificate has correct build config URI extension`:             factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}, "https://github.com/workflowRef"),
				`Certificate has correct build config digest extension`:          factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 19}, "workflowSHA"),
				`Certificate has correct build trigger extension`:                factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}, "trigger"),
				`Certificate has correct run invocation ID extension`:            factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}, "https://github.com/repository/actions/runs/runID/attempts/runAttempt"),
				`Certificate has correct source repository visibility extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 22}, "public"),
			},
		},
		`Github workflow value with bad URL fails`: {
			Principal: &Provider{},
			WantErr:   true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cert x509.Certificate
			err := test.Principal.Embed(context.TODO(), &cert)
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

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		for _, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(oid) {
				var strVal string
				_, _ = asn1.Unmarshal(ext.Value, &strVal)
				if value != strVal {
					return fmt.Errorf("expected oid %v to be %s, but got %s", oid, value, strVal)
				}
				return nil
			}
		}
		return errors.New("extension not set")
	}
}

func factDeprecatedExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
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
