// Copyright 2024 The Sigstore Authors.
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

//go:build !hermetic

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

type FulcioConfigMap struct {
	Data map[string]string `yaml:"data,omitempty"`
}

// It tests that the config/fulcio-config.yaml is properly parsable
func TestLoadFulcioConfig(t *testing.T) {
	_, path, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(path)
	b, err := os.ReadFile(basepath + "/../../config/config.yaml")
	if err != nil {
		t.Errorf("read file: %v", err)
	}

	cfg := FulcioConfigMap{}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Errorf("Unmarshal: %v", err)
	}

	fulcioConfig, err := Read([]byte(cfg.Data["config.yaml"]))
	if err != nil {
		t.Fatal(err)
	}

	for issuerURL := range fulcioConfig.OIDCIssuers {
		got, ok := fulcioConfig.GetIssuer(issuerURL)
		if !ok {
			t.Error("expected true, got false")
		}
		if got.ClientID != "sigstore" {
			t.Errorf("expected sigstore, got %s", got.ClientID)
		}
		if got.IssuerURL != issuerURL {
			t.Errorf("expected %s, got %s", issuerURL, got.IssuerURL)
		}
		if string(got.Type) == "" {
			t.Errorf("Issuer Type should not be empty")
		}
		if _, ok := fulcioConfig.GetIssuer("not_an_issuer"); ok {
			t.Error("no error returned from an unconfigured issuer")
		}
	}

	for _, metaIssuer := range fulcioConfig.MetaIssuers {
		if metaIssuer.ClientID != "sigstore" {
			t.Errorf("expected sigstore, got %s", metaIssuer.ClientID)
		}
	}
}
