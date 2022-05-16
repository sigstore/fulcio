// Copyright 2021 The Sigstore Authors.
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
//

package config

import (
	"testing"
)

var validCfg = `
{
	"OIDCIssuers": {
		"https://accounts.google.com": {
			"IssuerURL": "https://accounts.google.com",
			"ClientID": "foo"
		}
	},
	"MetaIssuers": {
		"https://oidc.eks.*.amazonaws.com/id/*": {
			"ClientID": "bar"
		}
	}
}
`

func TestMetaURLs(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		matches []string
		misses  []string
	}{{
		name:   "AWS meta URL",
		issuer: "https://oidc.eks.*.amazonaws.com/id/*",
		matches: []string{
			"https://oidc.eks.us-west-2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB",
		},
		misses: []string{
			// Extra dots
			"https://oidc.eks.us.west.2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB",
			// Extra slashes
			"https://oidc.eks.us-west/2.amazonaws.com/id/B02C93B6A2D3/0341AD01E1B6D48164CB",
		},
	}, {
		name:   "GKE meta URL",
		issuer: "https://container.googleapis.com/v1/projects/*/locations/*/clusters/*",
		matches: []string{
			"https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us-west1-b/clusters/tenant-cluster",
		},
		misses: []string{
			// Extra dots
			"https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us.west1.b/clusters/tenant-cluster",
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			re, err := metaRegex(test.issuer)
			if err != nil {
				t.Errorf("metaRegex() = %v", err)
			}

			for _, match := range test.matches {
				if !re.MatchString(match) {
					t.Errorf("MatchString(%q) = false, wanted true", match)
				}
			}

			for _, miss := range test.misses {
				if re.MatchString(miss) {
					t.Errorf("MatchString(%q) = true, wanted false", miss)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := map[string]struct {
		Config    *FulcioConfig
		WantError bool
	}{
		"good spiffe config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:         "issuer.example.com",
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "example.com",
					},
				},
			},
			WantError: false,
		},
		"spiffe issuer requires a trust domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeSpiffe,
					},
				},
			},
			WantError: true,
		},
		"spiffe issuer cannot be a meta issuer": {
			Config: &FulcioConfig{
				MetaIssuers: map[string]OIDCIssuer{
					"*.example.com": {
						ClientID:          "foo",
						Type:              IssuerTypeSpiffe,
						SPIFFETrustDomain: "example.com",
					},
				},
			},
			WantError: true,
		},
		"good uri config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: false,
		},
		"uri issuer requires a subject domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeURI,
					},
				},
			},
			WantError: true,
		},
		"nil config isn't valid": {
			Config:    nil,
			WantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateConfig(test.Config)
			if err != nil && !test.WantError {
				t.Error(err)
			}
			if err == nil && test.WantError {
				t.Error("expected error")
			}
		})
	}
}
