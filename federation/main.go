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

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/sigstore/fulcio/pkg/config"
	"gopkg.in/yaml.v3"
)

var rootPaths = []string{"federation", "federation/external"}
var boilerPlate = `#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
`

type federationConfig struct {
	URL               string
	Type              string
	IssuerClaim       string
	SpiffeTrustDomain string
	SkipClientIDCheck bool
}

func main() {
	matches := []string{}
	for _, rp := range rootPaths {
		glob := filepath.Join(rp, "*/config.yaml")
		globs, err := filepath.Glob(glob)
		if err != nil {
			panic(err)
		}
		matches = append(matches, globs...)
	}
	fulcioConfig := &config.FulcioConfig{
		OIDCIssuers: map[string]config.OIDCIssuer{},
		MetaIssuers: map[string]config.OIDCIssuer{
			// EKS Cluster OIDC issuers
			"https://oidc.eks.*.amazonaws.com/id/*": {
				ClientID: "sigstore",
				Type:     "kubernetes",
			},
			// GKE Cluster OIDC issuers
			"https://container.googleapis.com/v1/projects/*/locations/*/clusters/*": {
				ClientID: "sigstore",
				Type:     "kubernetes",
			},
			// AKS Cluster OIDC issuers
			"https://oidc.prod-aks.azure.com/*": {
				ClientID: "sigstore",
				Type:     "kubernetes",
			},
			"https://*.oic.prod-aks.azure.com/*": {
				ClientID: "sigstore",
				Type:     "kubernetes",
			},
		},
	}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			panic(err)
		}
		cfg := federationConfig{}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			panic(err)
		}

		fulcioCfg := config.OIDCIssuer{
			IssuerURL:         cfg.URL,
			ClientID:          "sigstore",
			Type:              config.IssuerType(cfg.Type),
			IssuerClaim:       cfg.IssuerClaim,
			SkipClientIDCheck: cfg.SkipClientIDCheck,
		}
		if fulcioCfg.Type == config.IssuerTypeSpiffe {
			fulcioCfg.SPIFFETrustDomain = cfg.SpiffeTrustDomain
		}
		fulcioConfig.OIDCIssuers[cfg.URL] = fulcioCfg
	}

	m, err := json.MarshalIndent(fulcioConfig, "", "  ")
	if err != nil {
		panic(err)
	}

	// Update the yaml
	yb, err := os.ReadFile("config/fulcio-config.yaml")
	if err != nil {
		panic(err)
	}

	cm := map[string]interface{}{}
	if err := yaml.Unmarshal(yb, &cm); err != nil {
		panic(err)
	}
	data := cm["data"].(map[string]interface{})
	data["config.json"] = string(m)

	newYaml, err := yaml.Marshal(cm)
	if err != nil {
		panic(err)
	}

	yamlWithBoilerplate := boilerPlate + string(newYaml)

	if err := os.WriteFile("config/fulcio-config.yaml", []byte(yamlWithBoilerplate), 0600); err != nil {
		panic(err)
	}
}
