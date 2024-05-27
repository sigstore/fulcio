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
	"os"

	"gopkg.in/yaml.v3"
)

type Extensions struct {
	Issuer                              string // OID 1.3.6.1.4.1.57264.1.8 and 1.3.6.1.4.1.57264.1.1 (Deprecated)
	Subject                             string
	GithubWorkflowTrigger               string `yaml:"github-workflow-trigger"`                 // OID 1.3.6.1.4.1.57264.1.2
	GithubWorkflowSHA                   string `yaml:"github-workflow-sha"`                     // OID 1.3.6.1.4.1.57264.1.3
	GithubWorkflowName                  string `yaml:"github-workflow-name"`                    // OID 1.3.6.1.4.1.57264.1.4
	GithubWorkflowRepository            string `yaml:"github-workflow-repository"`              // OID 1.3.6.1.4.1.57264.1.5
	GithubWorkflowRef                   string `yaml:"github-workflow-ref"`                     // 1.3.6.1.4.1.57264.1.6
	BuildSignerURI                      string `yaml:"build-signer-uri"`                        // 1.3.6.1.4.1.57264.1.9
	BuildSignerDigest                   string `yaml:"build-signer-digest"`                     // 1.3.6.1.4.1.57264.1.10
	RunnerEnvironment                   string `yaml:"runner-environment"`                      // 1.3.6.1.4.1.57264.1.11
	SourceRepositoryURI                 string `yaml:"source-repository-uri"`                   // 1.3.6.1.4.1.57264.1.12
	SourceRepositoryDigest              string `yaml:"source-repository-digest"`                // 1.3.6.1.4.1.57264.1.13
	SourceRepositoryRef                 string `yaml:"source-repository-ref"`                   // 1.3.6.1.4.1.57264.1.14
	SourceRepositoryIdentifier          string `yaml:"source-repository-identifier"`            // 1.3.6.1.4.1.57264.1.15
	SourceRepositoryOwnerURI            string `yaml:"source-repository-owner-uri"`             // 1.3.6.1.4.1.57264.1.16
	SourceRepositoryOwnerIdentifier     string `yaml:"source-repository-owner-identifier"`      // 1.3.6.1.4.1.57264.1.17
	BuildConfigURI                      string `yaml:"build-config-uri"`                        // 1.3.6.1.4.1.57264.1.18
	BuildConfigDigest                   string `yaml:"build-config-digest"`                     // 1.3.6.1.4.1.57264.1.19
	BuildTrigger                        string `yaml:"build-trigger"`                           // 1.3.6.1.4.1.57264.1.20
	RunInvocationURI                    string `yaml:"run-invocation-uri"`                      // 1.3.6.1.4.1.57264.1.21
	SourceRepositoryVisibilityAtSigning string `yaml:"source-repository-visibility-at-signing"` // 1.3.6.1.4.1.57264.1.22
}

type RootYaml struct {
	Providers map[string]Provider
}

type Provider struct {
	Extensions Extensions
	Uris       []string
	Defaults   map[string]string
}

func readYaml() RootYaml {
	var obj RootYaml

	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		fmt.Printf("yamlFile.Get err #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &obj)
	if err != nil {
		fmt.Printf("Unmarshal: %v", err)
	}

	return obj
}
