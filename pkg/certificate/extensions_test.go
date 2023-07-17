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
	"encoding/asn1"

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
				Issuer:                              "issuer", // OID 1.3.6.1.4.1.57264.1.1 and 1.3.6.1.4.1.57264.1.8
				GithubWorkflowTrigger:               "2",      // OID 1.3.6.1.4.1.57264.1.2
				GithubWorkflowSHA:                   "3",      // OID 1.3.6.1.4.1.57264.1.3
				GithubWorkflowName:                  "4",      // OID 1.3.6.1.4.1.57264.1.4
				GithubWorkflowRepository:            "5",      // OID 1.3.6.1.4.1.57264.1.5
				GithubWorkflowRef:                   "6",      // 1.3.6.1.4.1.57264.1.6
				BuildSignerURI:                      "9",      // 1.3.6.1.4.1.57264.1.9
				BuildSignerDigest:                   "10",     // 1.3.6.1.4.1.57264.1.10
				RunnerEnvironment:                   "11",     // 1.3.6.1.4.1.57264.1.11
				SourceRepositoryURI:                 "12",     // 1.3.6.1.4.1.57264.1.12
				SourceRepositoryDigest:              "13",     // 1.3.6.1.4.1.57264.1.13
				SourceRepositoryRef:                 "14",     // 1.3.6.1.4.1.57264.1.14
				SourceRepositoryIdentifier:          "15",     // 1.3.6.1.4.1.57264.1.15
				SourceRepositoryOwnerURI:            "16",     // 1.3.6.1.4.1.57264.1.16
				SourceRepositoryOwnerIdentifier:     "17",     // 1.3.6.1.4.1.57264.1.17
				BuildConfigURI:                      "18",     // 1.3.6.1.4.1.57264.1.18
				BuildConfigDigest:                   "19",     // 1.3.6.1.4.1.57264.1.19
				BuildTrigger:                        "20",     // 1.3.6.1.4.1.57264.1.20
				RunInvocationURI:                    "21",     // 1.3.6.1.4.1.57264.1.21
				SourceRepositoryVisibilityAtSigning: "22",     // 1.3.6.1.4.1.57264.1.22
			},
			Expect: []pkix.Extension{
				{
					Id:    OIDIssuer,
					Value: []byte("issuer"),
				},
				{
					Id:    OIDGitHubWorkflowTrigger,
					Value: []byte("2"),
				},
				{
					Id:    OIDGitHubWorkflowSHA,
					Value: []byte("3"),
				},
				{
					Id:    OIDGitHubWorkflowName,
					Value: []byte("4"),
				},
				{
					Id:    OIDGitHubWorkflowRepository,
					Value: []byte("5"),
				},
				{
					Id:    OIDGitHubWorkflowRef,
					Value: []byte("6"),
				},
				{
					Id:    OIDIssuerV2,
					Value: marshalDERString(t, "issuer"),
				},
				{
					Id:    OIDBuildSignerURI,
					Value: marshalDERString(t, "9"),
				},
				{
					Id:    OIDBuildSignerDigest,
					Value: marshalDERString(t, "10"),
				},
				{
					Id:    OIDRunnerEnvironment,
					Value: marshalDERString(t, "11"),
				},
				{
					Id:    OIDSourceRepositoryURI,
					Value: marshalDERString(t, "12"),
				},
				{
					Id:    OIDSourceRepositoryDigest,
					Value: marshalDERString(t, "13"),
				},
				{
					Id:    OIDSourceRepositoryRef,
					Value: marshalDERString(t, "14"),
				},
				{
					Id:    OIDSourceRepositoryIdentifier,
					Value: marshalDERString(t, "15"),
				},
				{
					Id:    OIDSourceRepositoryOwnerURI,
					Value: marshalDERString(t, "16"),
				},
				{
					Id:    OIDSourceRepositoryOwnerIdentifier,
					Value: marshalDERString(t, "17"),
				},
				{
					Id:    OIDBuildConfigURI,
					Value: marshalDERString(t, "18"),
				},
				{
					Id:    OIDBuildConfigDigest,
					Value: marshalDERString(t, "19"),
				},
				{
					Id:    OIDBuildTrigger,
					Value: marshalDERString(t, "20"),
				},
				{
					Id:    OIDRunInvocationURI,
					Value: marshalDERString(t, "21"),
				},
				{
					Id:    OIDSourceRepositoryVisibilityAtSigning,
					Value: marshalDERString(t, "22"),
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

			parse, err := parseExtensions(render)
			if err != nil {
				t.Fatalf("ParseExtensions: err = %v", err)
			}
			if diff := cmp.Diff(test.Extensions, parse); diff != "" {
				t.Errorf("ParseExtensions: %s", diff)
			}
		})
	}
}

func marshalDERString(t *testing.T, val string) []byte {
	derString, err := asn1.MarshalWithParams(val, "utf8")
	if err != nil {
		t.Fatalf("error marshalling string %v", err)
	}
	return derString
}

func TestParseDERString(t *testing.T) {
	input := []byte{0x13, 0x0b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}
	expected := "Hello World"
	var actual string
	err := ParseDERString(input, &actual)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if actual != expected {
		t.Errorf("unexpected result: got %q, want %q", actual, expected)
	}
}
