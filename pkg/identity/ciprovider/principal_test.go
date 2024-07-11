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
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
)

func TestWorkflowPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		ExpectedPrincipal ciPrincipal
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
			ExpectedPrincipal: ciPrincipal{
				ClaimsMetadata: config.IssuerMetadata{
					ExtensionTemplates: certificate.Extensions{
						Issuer:                              "issuer",
						GithubWorkflowTrigger:               "event_name",
						GithubWorkflowSHA:                   "sha",
						GithubWorkflowName:                  "workflow",
						GithubWorkflowRepository:            "repository",
						GithubWorkflowRef:                   "ref",
						BuildSignerURI:                      "{{ .url }}/{{ .job_workflow_ref }}",
						BuildSignerDigest:                   "job_workflow_sha",
						RunnerEnvironment:                   "runner_environment",
						SourceRepositoryURI:                 "{{ .url }}/{{ .repository }}",
						SourceRepositoryDigest:              "sha",
						SourceRepositoryRef:                 "ref",
						SourceRepositoryIdentifier:          "repository_id",
						SourceRepositoryOwnerURI:            "{{ .url }}/{{ .repository_owner }}",
						SourceRepositoryOwnerIdentifier:     "repository_owner_id",
						BuildConfigURI:                      "{{ .url }}/{{ .workflow_ref }}",
						BuildConfigDigest:                   "workflow_sha",
						BuildTrigger:                        "event_name",
						RunInvocationURI:                    "{{ .url }}/{{ .repository }}/actions/runs/{{ .run_id }}/attempts/{{ .run_attempt }}",
						SourceRepositoryVisibilityAtSigning: "repository_visibility",
					},
					DefaultTemplateValues: map[string]string{
						"url": "https://github.com",
					},
					SubjectAlternativeNameTemplate: "{{.url}}/{{.job_workflow_ref}}",
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			claims, err := json.Marshal(map[string]interface{}{
				"issuer":                "https://token.actions.githubusercontent.com",
				"event_name":            "trigger",
				"sha":                   "sha",
				"workflow":              "workflowname",
				"repository":            "repository",
				"ref":                   "ref",
				"job_workflow_sha":      "jobWorkflowSha",
				"job_workflow_ref":      "jobWorkflowRef",
				"runner_environment":    "runnerEnv",
				"repository_id":         "repoID",
				"repository_owner":      "repoOwner",
				"repository_owner_id":   "repoOwnerID",
				"workflow_ref":          "workflowRef",
				"workflow_sha":          "workflowSHA",
				"run_id":                "runID",
				"run_attempt":           "runAttempt",
				"repository_visibility": "public",
			})
			if err != nil {
				t.Fatal(err)
			}
			token := &oidc.IDToken{}
			withClaims(token, claims)

			test.ExpectedPrincipal.Token = token
			ctx := context.TODO()
			OIDCIssuers :=
				map[string]config.OIDCIssuer{
					token.Issuer: {
						IssuerURL:  token.Issuer,
						Type:       config.IssuerTypeCIProvider,
						CIProvider: "github-workflow",
						ClientID:   "sigstore",
					},
				}
			meta := make(map[string]config.IssuerMetadata)
			meta["github-workflow"] = test.ExpectedPrincipal.ClaimsMetadata
			cfg := &config.FulcioConfig{
				OIDCIssuers:      OIDCIssuers,
				CIIssuerMetadata: meta,
			}
			ctx = config.With(ctx, cfg)
			principal, err := WorkflowPrincipalFromIDToken(ctx, token)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(principal, test.ExpectedPrincipal) {
				t.Error("Principals should be equals")
			}
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
						IssuerURL:  token.Issuer,
						Type:       config.IssuerTypeCIProvider,
						CIProvider: "ci-provider",
						ClientID:   "sigstore",
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

func TestApplyTemplateOrReplace(t *testing.T) {

	tokenClaims := map[string]string{
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
	}
	issuerMetadata := map[string]string{
		"url": "https://github.com",
	}

	tests := map[string]struct {
		Template       string
		ExpectedResult string
		ExpectErr      bool
	}{
		`Valid template`: {
			Template:       "{{ .url }}/{{ .repository }}/actions/runs/{{ .run_id }}/attempts/{{ .run_attempt }}",
			ExpectedResult: "https://github.com/sigstore/fulcio/actions/runs/42/attempts/1",
			ExpectErr:      false,
		},
		`Empty template`: {
			Template:       "{{}}",
			ExpectedResult: "",
			ExpectErr:      true,
		},
		`Missing key for template`: {
			Template:       "{{ .foo }}",
			ExpectedResult: "",
			ExpectErr:      true,
		},
		`Empty string`: {
			Template:       "",
			ExpectedResult: "",
			ExpectErr:      true,
		},
		`Replaceable string`: {
			Template:       "job_workflow_ref",
			ExpectedResult: "sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
			ExpectErr:      false,
		},
		`Missing string`: {
			Template:       "bar",
			ExpectedResult: "",
			ExpectErr:      true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := applyTemplateOrReplace(test.Template, tokenClaims, issuerMetadata)
			if res != test.ExpectedResult {
				t.Errorf("expected result don't matches: Expected %s, received: %s",
					test.ExpectedResult, res)
			}
			if (err != nil) != test.ExpectErr {
				t.Errorf("should raise an error don't matches: Expected %v, received: %v",
					test.ExpectErr, err != nil)
			}
		})
	}
}

func TestEmbed(t *testing.T) {
	tests := map[string]struct {
		WantFacts map[string]func(x509.Certificate) error
		Principal ciPrincipal
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
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
			Principal: ciPrincipal{
				ClaimsMetadata: config.IssuerMetadata{
					ExtensionTemplates: certificate.Extensions{
						GithubWorkflowTrigger:               "event_name",
						GithubWorkflowSHA:                   "sha",
						GithubWorkflowName:                  "workflow",
						GithubWorkflowRepository:            "repository",
						GithubWorkflowRef:                   "ref",
						BuildSignerURI:                      "{{ .url }}/{{ .job_workflow_ref }}",
						BuildSignerDigest:                   "job_workflow_sha",
						RunnerEnvironment:                   "runner_environment",
						SourceRepositoryURI:                 "{{ .url }}/{{ .repository }}",
						SourceRepositoryDigest:              "sha",
						SourceRepositoryRef:                 "ref",
						SourceRepositoryIdentifier:          "repository_id",
						SourceRepositoryOwnerURI:            "{{ .url }}/{{ .repository_owner }}",
						SourceRepositoryOwnerIdentifier:     "repository_owner_id",
						BuildConfigURI:                      "{{ .url }}/{{ .workflow_ref }}",
						BuildConfigDigest:                   "workflow_sha",
						BuildTrigger:                        "event_name",
						RunInvocationURI:                    "{{ .url }}/{{ .repository }}/actions/runs/{{ .run_id }}/attempts/{{ .run_attempt }}",
						SourceRepositoryVisibilityAtSigning: "repository_visibility",
					},
					DefaultTemplateValues: map[string]string{
						"url": "https://github.com",
					},
					SubjectAlternativeNameTemplate: "{{.url}}/{{.job_workflow_ref}}",
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cert x509.Certificate
			claims, err := json.Marshal(map[string]interface{}{
				"event_name":            "trigger",
				"sha":                   "sha",
				"workflow":              "workflowname",
				"repository":            "repository",
				"ref":                   "ref",
				"job_workflow_sha":      "jobWorkflowSha",
				"job_workflow_ref":      "jobWorkflowRef",
				"runner_environment":    "runnerEnv",
				"repository_id":         "repoID",
				"repository_owner":      "repoOwner",
				"repository_owner_id":   "repoOwnerID",
				"workflow_ref":          "workflowRef",
				"workflow_sha":          "workflowSHA",
				"run_id":                "runID",
				"run_attempt":           "runAttempt",
				"repository_visibility": "public",
			})
			if err != nil {
				t.Fatal(err)
			}
			token := &oidc.IDToken{}
			token.Issuer = "https://token.actions.githubusercontent.com"
			withClaims(token, claims)

			test.Principal.Token = token
			err = test.Principal.Embed(context.TODO(), &cert)
			if err != nil {
				t.Error(err)
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
