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

package buildkite

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
				"aud":               "sigstore",
				"build_number":      123,
				"exp":               0,
				"iss":               "https://agent.buildkite.com",
				"job_id":            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
				"organization_slug": "acme-inc",
				"pipeline_slug":     "bash-example",
				"sub":               "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			ExpectPrincipal: jobPrincipal{
				issuer:  "https://agent.buildkite.com",
				subject: "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
				url:     "https://buildkite.com/acme-inc/bash-example/builds/123#f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
			},
			WantErr: false,
		},
		`Token missing build_number claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":               "sigstore",
				"exp":               0,
				"iss":               "https://agent.buildkite.com",
				"job_id":            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
				"organization_slug": "acme-inc",
				"pipeline_slug":     "bash-example",
				"sub":               "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			WantErr:     true,
			ErrContains: "build_number",
		},
		`Token missing job_id claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":               "sigstore",
				"build_number":      123,
				"exp":               0,
				"iss":               "https://agent.buildkite.com",
				"organization_slug": "acme-inc",
				"pipeline_slug":     "bash-example",
				"sub":               "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			WantErr:     true,
			ErrContains: "job_id",
		},
		`Token missing organization_slug claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":           "sigstore",
				"build_number":  123,
				"exp":           0,
				"iss":           "https://agent.buildkite.com",
				"job_id":        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
				"pipeline_slug": "bash-example",
				"sub":           "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			WantErr:     true,
			ErrContains: "organization_slug",
		},
		`Token missing pipeline_slug claim should be rejected`: {
			Claims: map[string]interface{}{
				"aud":               "sigstore",
				"build_number":      123,
				"exp":               0,
				"iss":               "https://agent.buildkite.com",
				"job_id":            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
				"organization_slug": "acme-inc",
				"sub":               "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			WantErr:     true,
			ErrContains: "pipeline_slug",
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
				"aud":               "sigstore",
				"build_number":      123,
				"exp":               0,
				"iss":               "https://agent.buildkite.com",
				"job_id":            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
				"organization_slug": "acme-inc",
				"pipeline_slug":     "bash-example",
				"sub":               "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
			},
			ExpectName: "organization:acme-inc:pipeline:bash-example:ref:refs/heads/main:commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:step:build",
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
		`Buildkite job challenge should have issue, subject and url embedded`: {
			Principal: &jobPrincipal{
				issuer:  "https://agent.buildkite.com",
				subject: "doesntmatter",
				url:     `https://buildkite.com/foo/bar`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`: factIssuerIs(`https://agent.buildkite.com`),
			},
		},
		`Buildkite job principal with bad URL fails`: {
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
