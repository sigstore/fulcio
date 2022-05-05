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
	"context"
	"crypto/x509"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestPrincipal(t *testing.T) {
	/* Example claims from https://awsteele.com/blog/2021/09/15/aws-federation-comes-to-github-actions.html
	   {
	     "actor": "aidansteele",
	     "aud": "sigstore",
	     "base_ref": "",
	     "event_name": "push",
	     "exp": 1631672856,
	     "head_ref": "",
	     "iat": 1631672556,
	     "iss": "https://token.actions.githubusercontent.com",
	     "job_workflow_ref": "aidansteele/aws-federation-github-actions/.github/workflows/test.yml@refs/heads/main",
	     "jti": "8ea8373e-0f9d-489d-a480-ac37deexample",
	     "nbf": 1631671956,
	     "ref": "refs/heads/main",
	     "ref_type": "branch",
	     "repository": "aidansteele/aws-federation-github-actions",
	     "repository_owner": "aidansteele",
	     "run_attempt": "1",
	     "run_id": "1235992580",
	     "run_number": "5",
	     "sha": "bf96275471e83ff04ce5c8eb515c04a75d43f854",
	     "sub": "repo:aidansteele/aws-federation-github-actions:ref:refs/heads/main",
	     "workflow": "CI"
	   }
	*/
	// Token matches claims above
	token := `eyJhbGciOiJSUzI1NiIsImtpZCI6Imptczl3WWdPcmxUWjZsSzZTZ2FfaE1JNDZHcXJXYUhicWZfdHJuZ1NxbDAiLCJ0eXAiOiJKV1QifQ.eyJhY3RvciI6ImFpZGFuc3RlZWxlIiwiYXVkIjoic2lnc3RvcmUiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJwdXNoIiwiZXhwIjoxLjYzMTY3Mjg1NmUrMDksImhlYWRfcmVmIjoiIiwiaWF0IjoxLjYzMTY3MjU1NmUrMDksImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20iLCJqb2Jfd29ya2Zsb3dfcmVmIjoiYWlkYW5zdGVlbGUvYXdzLWZlZGVyYXRpb24tZ2l0aHViLWFjdGlvbnMvLmdpdGh1Yi93b3JrZmxvd3MvdGVzdC55bWxAcmVmcy9oZWFkcy9tYWluIiwianRpIjoiOGVhODM3M2UtMGY5ZC00ODlkLWE0ODAtYWMzN2RlZXhhbXBsZSIsIm5iZiI6MS42MzE2NzE5NTZlKzA5LCJyZWYiOiJyZWZzL2hlYWRzL21haW4iLCJyZWZfdHlwZSI6ImJyYW5jaCIsInJlcG9zaXRvcnkiOiJhaWRhbnN0ZWVsZS9hd3MtZmVkZXJhdGlvbi1naXRodWItYWN0aW9ucyIsInJlcG9zaXRvcnlfb3duZXIiOiJhaWRhbnN0ZWVsZSIsInJ1bl9hdHRlbXB0IjoiMSIsInJ1bl9pZCI6IjEyMzU5OTI1ODAiLCJydW5fbnVtYmVyIjoiNSIsInNoYSI6ImJmOTYyNzU0NzFlODNmZjA0Y2U1YzhlYjUxNWMwNGE3NWQ0M2Y4NTQiLCJzdWIiOiJyZXBvOmFpZGFuc3RlZWxlL2F3cy1mZWRlcmF0aW9uLWdpdGh1Yi1hY3Rpb25zOnJlZjpyZWZzL2hlYWRzL21haW4iLCJ3b3JrZmxvdyI6IkNJIn0.BCQD4kedZDzF_3IphHH4pr6cTYQzO9d0orFocvqZSSWH6hHYMw3PJ5YlAleEuXNxgVmMtHN6USrxbfa3bXXshhluSXiV4TVlPc2s8fFXNiLg9TwbXFkDDm_IfYZInHeS5By2AifbT0MPCebPnhYvVR1nUIAjZnU1lcgiN20rZFCV`
	issuer := actionsIssuer{
		IDTokenVerifier: oidc.NewVerifier(
			`https://token.actions.githubusercontent.com`,
			&testKeySet{},
			&oidc.Config{
				ClientID:        `sigstore`,
				SkipExpiryCheck: true,
			},
		)}
	ctx := context.TODO()

	principal, err := issuer.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}

	// Verify principal name matches full URL of workflow
	if principal.Name(ctx) != `https://github.com/aidansteele/aws-federation-github-actions/.github/workflows/test.yml@refs/heads/main` {
		t.Error(`Wrong principal name`)
	}

	// Verify correct fields are embedded into certificate
	var cert x509.Certificate
	err = principal.Embed(ctx, &cert)
	if err != nil {
		t.Error(err)
	}

	if len(cert.URIs) != 1 {
		t.Error(`Should have embedded exactly one SAN URI`)
	}
	if len(cert.ExtraExtensions) != 6 {
		// issuer, sha, trigger, workflow, ref and repo
		t.Error(`Should have embedded exactly 6 extra extensions`)
	}
}
