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
	"fmt"
	"net/url"
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
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: false,
		},
		"uri issuer requires a subject domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "https://issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeURI,
					},
				},
			},
			WantError: true,
		},
		"uri subject domain should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer url should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer and subject domains must have same top-level hostname": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "https://different.com",
					},
				},
			},
			WantError: true,
		},
		"uri issuer and subject domains must have same scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://example.com",
						ClientID:      "foo",
						Type:          IssuerTypeURI,
						SubjectDomain: "http://example.com",
					},
				},
			},
			WantError: true,
		},
		"good username config": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: false,
		},
		"username issuer requires a subject domain": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL: "https://issuer.example.com",
						ClientID:  "foo",
						Type:      IssuerTypeUsername,
					},
				},
			},
			WantError: true,
		},
		"username subject domain should not contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "https://other.example.com",
					},
				},
			},
			WantError: true,
		},
		"username issuer url should contain scheme": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "other.example.com",
					},
				},
			},
			WantError: true,
		},
		"username issuer and subject domains must have same top-level hostname": {
			Config: &FulcioConfig{
				OIDCIssuers: map[string]OIDCIssuer{
					"issuer.example.com": {
						IssuerURL:     "https://issuer.example.com",
						ClientID:      "foo",
						Type:          IssuerTypeUsername,
						SubjectDomain: "different.com",
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
				t.Errorf("%s: %v", name, err)
			}
			if err == nil && test.WantError {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}

func Test_isURISubjectAllowed(t *testing.T) {
	tests := []struct {
		name    string
		subject string // Parsed to url.URL
		issuer  string // Parsed to url.URL
		want    error
	}{{
		name:    "match",
		subject: "https://accounts.example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "issuer subdomain",
		subject: "https://example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "subject subdomain",
		subject: "https://profiles.example.com",
		issuer:  "https://example.com",
		want:    nil,
	}, {
		name:    "subdomain mismatch",
		subject: "https://profiles.example.com",
		issuer:  "https://accounts.example.com",
		want:    nil,
	}, {
		name:    "scheme mismatch",
		subject: "http://example.com",
		issuer:  "https://example.com",
		want:    fmt.Errorf("subject (http) and issuer (https) URI schemes do not match"),
	}, {
		name:    "subject domain too short",
		subject: "https://example",
		issuer:  "https://example.com",
		want:    fmt.Errorf("URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "https://example.com",
		issuer:  "https://issuer",
		want:    fmt.Errorf("URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "https://example.com",
		issuer:  "https://otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "https://example.com",
		issuer:  "https://example.org",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, example.org"),
	}}
	for _, tt := range tests {
		subject, _ := url.Parse(tt.subject)
		issuer, _ := url.Parse(tt.issuer)
		t.Run(tt.name, func(t *testing.T) {
			got := isURISubjectAllowed(subject, issuer)
			if got == nil && tt.want != nil ||
				got != nil && tt.want == nil {
				t.Errorf("isURISubjectAllowed() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Error() != tt.want.Error() {
				t.Errorf("isURISubjectAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateAllowedDomain(t *testing.T) {
	tests := []struct {
		name    string
		subject string // Parsed to url.URL
		issuer  string // Parsed to url.URL
		want    error
	}{{
		name:    "match",
		subject: "accounts.example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "issuer subdomain",
		subject: "example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "subject subdomain",
		subject: "profiles.example.com",
		issuer:  "example.com",
		want:    nil,
	}, {
		name:    "subdomain mismatch",
		subject: "profiles.example.com",
		issuer:  "accounts.example.com",
		want:    nil,
	}, {
		name:    "subject domain too short",
		subject: "example",
		issuer:  "example.com",
		want:    fmt.Errorf("URI hostname too short: example"),
	}, {
		name:    "issuer domain too short",
		subject: "example.com",
		issuer:  "issuer",
		want:    fmt.Errorf("URI hostname too short: issuer"),
	}, {
		name:    "domain mismatch",
		subject: "example.com",
		issuer:  "otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, otherexample.com"),
	}, {
		name:    "domain mismatch, subdomain match",
		subject: "test.example.com",
		issuer:  "test.otherexample.com",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: test.example.com, test.otherexample.com"),
	}, {
		name:    "top level domain mismatch",
		subject: "example.com",
		issuer:  "example.org",
		want:    fmt.Errorf("hostname top-level and second-level domains do not match: example.com, example.org"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateAllowedDomain(tt.subject, tt.issuer)
			if got == nil && tt.want != nil ||
				got != nil && tt.want == nil {
				t.Errorf("validateAllowedDomain() = %v, want %v", got, tt.want)
			}
			if got != nil && tt.want != nil && got.Error() != tt.want.Error() {
				t.Errorf("validateAllowedDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
