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
	"bytes"
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
				issuer:  "https://gitlab.com",
				subject: "doesntmatter",
				url:     `https://gitlab.com/honk/honk-repo/-/job/123456`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`: factIssuerIs(`https://gitlab.com`),
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

func factIssuerIs(issuer string) func(x509.Certificate) error {
	return factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, issuer)
}

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
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
