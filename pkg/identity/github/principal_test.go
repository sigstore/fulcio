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

func TestWorkflowPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal workflowPrincipal
		WantErr         bool
		ErrContains     string
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
				issuer:     "https://token.actions.githubusercontent.com",
				subject:    "repo:sigstore/fulcio:ref:refs/heads/main",
				url:        "https://github.com/sigstore/fulcio/.github/workflows/foo.yaml@refs/heads/main",
				sha:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				trigger:    "push",
				repository: "sigstore/fulcio",
				workflow:   "foo",
				ref:        "refs/heads/main",
			},
			WantErr: false,
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
			WantErr:     true,
			ErrContains: "job_workflow_ref",
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
			WantErr:     true,
			ErrContains: "sha",
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
			WantErr:     true,
			ErrContains: "event_name",
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
			WantErr:     true,
			ErrContains: "repository",
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
			WantErr:     true,
			ErrContains: "workflow",
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
			WantErr:     true,
			ErrContains: "ref",
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

			untyped, err := WorkflowPrincipalFromIDToken(context.TODO(), token)
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

			principal, ok := untyped.(*workflowPrincipal)
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
			Principal: &workflowPrincipal{
				issuer:     "https://token.actions.githubusercontent.com",
				subject:    "doesntmatter",
				url:        `https://github.com/foo/bar/`,
				sha:        "sha",
				trigger:    "trigger",
				workflow:   "workflowname",
				repository: "repository",
				ref:        "ref",
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`:     factIssuerIs(`https://token.actions.githubusercontent.com`),
				`Certificate has correct trigger extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, "trigger"),
				`Certificate has correct SHA extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, "sha"),
				`Certificate has correct workflow extension`:   factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, "workflowname"),
				`Certificate has correct repository extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, "repository"),
				`Certificate has correct ref extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, "ref"),
			},
		},
		`Github workflow value with bad URL fails`: {
			Principal: &workflowPrincipal{
				subject:    "doesntmatter",
				url:        "\nbadurl",
				sha:        "sha",
				trigger:    "trigger",
				workflow:   "workflowname",
				repository: "repository",
				ref:        "ref",
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
