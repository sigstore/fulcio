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

package certificate

import (
	"crypto/x509/pkix"

	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtensions(t *testing.T) {
	tests := map[string]struct {
		Extensions Extensions
		Expect     []pkix.Extension
		WantErr    bool
	}{
		`Missing issuer extension leads to render error`: {
			Extensions: Extensions{
				GithubWorkflowTrigger: `foo`,
			},
			WantErr: true,
		},
		`complete extensions list should create all extensions with correct OIDs`: {
			Extensions: Extensions{
				Issuer:                   `1`, // OID 1.3.6.1.4.1.57264.1.1
				GithubWorkflowTrigger:    `2`, // OID 1.3.6.1.4.1.57264.1.2
				GithubWorkflowSHA:        `3`, // OID 1.3.6.1.4.1.57264.1.3
				GithubWorkflowName:       `4`, // OID 1.3.6.1.4.1.57264.1.4
				GithubWorkflowRepository: `5`, // OID 1.3.6.1.4.1.57264.1.5
				GithubWorkflowRef:        `6`, // 1.3.6.1.4.1.57264.1.6
			},
			Expect: []pkix.Extension{
				{
					Id:    OIDIssuer,
					Value: []byte(`1`),
				},
				{
					Id:    OIDGitHubWorkflowTrigger,
					Value: []byte(`2`),
				},
				{
					Id:    OIDGitHubWorkflowSHA,
					Value: []byte(`3`),
				},
				{
					Id:    OIDGitHubWorkflowName,
					Value: []byte(`4`),
				},
				{
					Id:    OIDGitHubWorkflowRepository,
					Value: []byte(`5`),
				},
				{
					Id:    OIDGitHubWorkflowRef,
					Value: []byte(`6`),
				},
			},
			WantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			render, err := test.Extensions.Render()
			if err != nil {
				if !test.WantErr {
					t.Error("Failed to render with unexpected error", err)
				} else {
					return
				}
			}
			if diff := cmp.Diff(test.Expect, render); diff != "" {
				t.Errorf("Render: %s", diff)
			}

			parse, err := ParseExtensions(render)
			if err != nil {
				t.Fatalf("ParseExtensions: err = %v", err)
			}
			if diff := cmp.Diff(test.Extensions, parse); diff != "" {
				t.Errorf("ParseExtensions: %s", diff)
			}
		})
	}
}
