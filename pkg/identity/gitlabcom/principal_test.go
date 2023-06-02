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
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestJobPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal jobPrincipal
		WantErr         bool
		ErrContains     string
	}{
		`Valid token authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"aud":                "sigstore",
				"exp":                0,
				"iss":                "https://gitlab.com",
				"sub":                "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				"project_id":         "42831435",
				"project_path":       "cpanato/testing-cosign",
				"namespace_path":     "cpanato",
				"namespace_id":       "1730270",
				"pipeline_id":        "757451528",
				"pipeline_source":    "push",
				"pipeline_ref":       "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				"pipeline_sha":       "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"job_id":             "3659681386",
				"ref":                "main",
				"ref_type":           "branch",
				"sha":                "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"runner_id":          1,
				"runner_environment": "gitlab-hosted",
			},
			ExpectPrincipal: jobPrincipal{
				issuer:            "https://gitlab.com",
				subject:           "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				url:               "https://gitlab.com/",
				eventName:         "push",
				pipelineID:        "757451528",
				pipelineRef:       "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				pipelineSha:       "714a629c0b401fdce83e847fc9589983fc6f46bc",
				repository:        "cpanato/testing-cosign",
				repositoryID:      "42831435",
				repositoryOwner:   "cpanato",
				repositoryOwnerID: "1730270",
				jobID:             "3659681386",
				ref:               "refs/heads/main",
				runnerID:          1,
				runnerEnvironment: "gitlab-hosted",
				sha:               "714a629c0b401fdce83e847fc9589983fc6f46bc",
			},
			WantErr: false,
		},
		`Token missing pipeline_source claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":            "sigstore",
				"exp":            0,
				"iss":            "https://gitlab.com",
				"sub":            "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				"pipeline_ref":   "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				"pipeline_sha":   "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"project_id":     "42831435",
				"project_path":   "cpanato/testing-cosign",
				"namespace_path": "cpanato",
				"namespace_id":   "1730270",
				"pipeline_id":    "757451528",
				"job_id":         "3659681386",
				"ref":            "main",
				"ref_type":       "branch",
			},
			WantErr:     true,
			ErrContains: "pipeline_source",
		},
		`Token missing project_path claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":             "sigstore",
				"exp":             0,
				"iss":             "https://gitlab.com",
				"sub":             "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				"pipeline_ref":    "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				"pipeline_sha":    "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"project_id":      "42831435",
				"pipeline_id":     "757451528",
				"namespace_id":    "1730270",
				"pipeline_source": "push",
				"namespace_path":  "cpanato",
				"job_id":          "3659681386",
				"ref":             "main",
				"ref_type":        "branch",
			},
			WantErr:     true,
			ErrContains: "project_path",
		},
		`Token missing pipeline_sha claim is ok`: {
			Claims: map[string]interface{}{
				"aud":                "sigstore",
				"exp":                0,
				"iss":                "https://gitlab.com",
				"sub":                "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				"project_id":         "42831435",
				"project_path":       "cpanato/testing-cosign",
				"namespace_path":     "cpanato",
				"namespace_id":       "1730270",
				"pipeline_id":        "757451528",
				"pipeline_source":    "push",
				"pipeline_ref":       "example.com/ci/config.yml",
				"job_id":             "3659681386",
				"ref":                "main",
				"ref_type":           "branch",
				"sha":                "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"runner_id":          1,
				"runner_environment": "gitlab-hosted",
			},
			ExpectPrincipal: jobPrincipal{
				issuer:            "https://gitlab.com",
				subject:           "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				url:               "https://gitlab.com/",
				eventName:         "push",
				pipelineID:        "757451528",
				pipelineRef:       "example.com/ci/config.yml",
				repository:        "cpanato/testing-cosign",
				repositoryID:      "42831435",
				repositoryOwner:   "cpanato",
				repositoryOwnerID: "1730270",
				jobID:             "3659681386",
				ref:               "refs/heads/main",
				runnerID:          1,
				runnerEnvironment: "gitlab-hosted",
				sha:               "714a629c0b401fdce83e847fc9589983fc6f46bc",
			},
			WantErr: false,
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

			untyped, err := JobPrincipalFromIDToken(context.TODO(), token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				if !strings.Contains(err.Error(), test.ErrContains) {
					t.Fatalf("expected error %s to contain %s", err, test.ErrContains)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			principal, ok := untyped.(*jobPrincipal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if *principal != test.ExpectPrincipal {
				t.Errorf("got %v principal and expected %v", *principal, test.ExpectPrincipal)
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
				"aud":                "sigstore",
				"exp":                0,
				"iss":                "https://gitlab.com",
				"sub":                "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				"project_id":         "42831435",
				"project_path":       "cpanato/testing-cosign",
				"pipeline_id":        "757451528",
				"pipeline_ref":       "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				"pipeline_source":    "push",
				"namespace_path":     "cpanato",
				"namespace_id":       "1730270",
				"job_id":             "3659681386",
				"ref":                "main",
				"ref_type":           "branch",
				"sha":                "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"runner_id":          1,
				"runner_environment": "gitlab-hosted",
			},
			ExpectName: "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
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

			principal, err := JobPrincipalFromIDToken(context.TODO(), token)
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
		`GitLab job challenge should have issue, subject and url embedded`: {
			Principal: &jobPrincipal{
				issuer:            "https://gitlab.com",
				subject:           "project_path:cpanato/testing-cosign:ref_type:branch:ref:main",
				url:               "https://gitlab.com/",
				eventName:         "push",
				pipelineID:        "757451528",
				pipelineRef:       "gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main",
				pipelineSha:       "714a629c0b401fdce83e847fc9589983fc6f46bc",
				repository:        "cpanato/testing-cosign",
				repositoryID:      "42831435",
				repositoryOwner:   "cpanato",
				repositoryOwnerID: "1730270",
				jobID:             "3659681386",
				ref:               "ref",
				runnerID:          1,
				runnerEnvironment: "gitlab-hosted",
				sha:               "sha",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certificate has correct issuer (v2) extension`:           factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, "https://gitlab.com"),
				`Certificate has correct builder signer URI extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}, "https://gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main"),
				`Certificate has correct builder signer digest extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}, "714a629c0b401fdce83e847fc9589983fc6f46bc"),
				`Certificate has correct runner environment extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}, "gitlab-hosted"),
				`Certificate has correct source repo URI extension`:       factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}, "https://gitlab.com/cpanato/testing-cosign"),
				`Certificate has correct source repo digest extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}, "sha"),
				`Certificate has correct source repo ref extension`:       factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}, "ref"),
				`Certificate has correct source repo ID extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}, "42831435"),
				`Certificate has correct source repo owner URI extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 16}, "https://gitlab.com/cpanato"),
				`Certificate has correct source repo owner ID extension`:  factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}, "1730270"),
				`Certificate has correct build config URI extension`:      factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}, "https://gitlab.com/cpanto/testing-cosign/.gitlab-ci.yml@refs/head/main"),
				`Certificate has correct build config digest extension`:   factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 19}, "714a629c0b401fdce83e847fc9589983fc6f46bc"),
				`Certificate has correct build trigger extension`:         factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}, "push"),
				`Certificate has correct run invocation ID extension`:     factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}, "https://gitlab.com/cpanato/testing-cosign/-/jobs/3659681386"),
			},
		},
		`GitLab job principal with bad URL fails`: {
			Principal: &jobPrincipal{
				subject: "doesntmatter",
				url:     "\nbadurl",
			},
			WantErr: true,
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
