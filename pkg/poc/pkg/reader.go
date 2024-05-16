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
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type PreExtensions struct {
	Fields []string

	Issuer []string // OID 1.3.6.1.4.1.57264.1.8 and 1.3.6.1.4.1.57264.1.1 (Deprecated)

	GithubWorkflowTrigger []string // OID 1.3.6.1.4.1.57264.1.2

	GithubWorkflowSHA []string // OID 1.3.6.1.4.1.57264.1.3

	GithubWorkflowName []string // OID 1.3.6.1.4.1.57264.1.4

	GithubWorkflowRepository []string // OID 1.3.6.1.4.1.57264.1.5

	GithubWorkflowRef []string // 1.3.6.1.4.1.57264.1.6

	BuildSignerURI []string // 1.3.6.1.4.1.57264.1.9

	BuildSignerDigest []string // 1.3.6.1.4.1.57264.1.10

	RunnerEnvironment []string // 1.3.6.1.4.1.57264.1.11

	SourceRepositoryURI []string // 1.3.6.1.4.1.57264.1.12

	SourceRepositoryDigest []string // 1.3.6.1.4.1.57264.1.13

	SourceRepositoryRef []string // 1.3.6.1.4.1.57264.1.14

	SourceRepositoryIdentifier []string // 1.3.6.1.4.1.57264.1.15

	SourceRepositoryOwnerURI []string // 1.3.6.1.4.1.57264.1.16

	SourceRepositoryOwnerIdentifier []string // 1.3.6.1.4.1.57264.1.17

	BuildConfigURI []string // 1.3.6.1.4.1.57264.1.18

	BuildConfigDigest []string // 1.3.6.1.4.1.57264.1.19

	BuildTrigger []string // 1.3.6.1.4.1.57264.1.20

	RunInvocationURI []string // 1.3.6.1.4.1.57264.1.21

	SourceRepositoryVisibilityAtSigning []string // 1.3.6.1.4.1.57264.1.22
}

type PreYaml struct {
	Providers map[string]PreExtensions
}

func main() {
	var obj PreYaml

	yamlFile, err := os.ReadFile("pkg/providers.yaml")
	if err != nil {
		fmt.Printf("yamlFile.Get err #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &obj)
	if err != nil {
		fmt.Printf("Unmarshal: %v", err)
	}

	fmt.Println(obj)

}
