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

package x509ca

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"

	"testing"
)

func TestRenderExtensions(t *testing.T) {
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
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
					Value: []byte(`1`),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2},
					Value: []byte(`2`),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3},
					Value: []byte(`3`),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4},
					Value: []byte(`4`),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5},
					Value: []byte(`5`),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6},
					Value: []byte(`6`),
				},
			},
			WantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := test.Extensions.Render()
			if err != nil {
				if !test.WantErr {
					t.Error("Failed to render with unexpected error", err)
				} else {
					return
				}
			}
			if len(got) != len(test.Expect) {
				t.Errorf("Got %d extensions when rendered and expected %d", len(got), len(test.Expect))
				return
			}
			for i, ext := range got {
				if !ext.Id.Equal(test.Expect[i].Id) {
					t.Errorf("Got OID %v in extension %d and expected %v", ext.Id, i, test.Expect[i].Id)
				}
				if !bytes.Equal(ext.Value, test.Expect[i].Value) {
					t.Errorf("Expected extension value to be %s but got %s", test.Expect[i].Value, ext.Value)
				}
			}
		})
	}
}
