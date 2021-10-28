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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestLoad(t *testing.T) {
	td := t.TempDir()
	cfgPath := filepath.Join(td, "config.json")
	if err := ioutil.WriteFile(cfgPath, []byte(validCfg), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfgPath); err != nil {
		t.Fatal(err)
	}

	cfg := Config()
	got, ok := cfg.GetIssuer("https://accounts.google.com")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "foo" {
		t.Errorf("expected foo, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://accounts.google.com" {
		t.Errorf("expected https://accounts.google.com, got %s", got.IssuerURL)
	}
	if got := len(cfg.OIDCIssuers); got != 1 {
		t.Errorf("expected 1 issuer, got %d", got)
	}

	got, ok = cfg.GetIssuer("https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "bar" {
		t.Errorf("expected bar, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER" {
		t.Errorf("expected https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER, got %s", got.IssuerURL)
	}
}

func TestLoadDefaults(t *testing.T) {
	td := t.TempDir()

	// Don't put anything here!
	cfgPath := filepath.Join(td, "config.json")
	if err := Load(cfgPath); err != nil {
		t.Fatal(err)
	}

	cfg := Config()

	if diff := cmp.Diff(DefaultConfig, cfg, cmpopts.IgnoreUnexported(FulcioConfig{})); diff != "" {
		t.Errorf("DefaultConfig(): -want +got: %s", diff)

	}
}
