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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// Extensions contains all custom x509 extensions defined by Fulcio
type Extensions struct {
	// NB: New extensions must be added here and documented
	// at docs/oidc-info.md

	// The OIDC issuer. Should match `iss` claim of ID token or, in the case
	// of a federated login like Dex it should match the issuer URL of the upstream
	// issuer
	Issuer string // OID 1.3.6.1.4.1.57264.1.1

	// Triggering event of the Github Workflow. Matches the `event_name` claim of ID
	// tokens from Github Actions
	GithubWorkflowTrigger string // OID 1.3.6.1.4.1.57264.1.2

	// SHA of git commit being built in Github Actions. Matches the `sha` claim of ID
	// tokens from Github Actions
	GithubWorkflowSHA string // OID 1.3.6.1.4.1.57264.1.3

	// Name of Github Actions Workflow. Matches the `workflow` claim of the ID
	// tokens from Github Actions
	GithubWorkflowName string // OID 1.3.6.1.4.1.57264.1.4

	// Repository of the Github Actions Workflow. Matches the `repository` claim of the ID
	// tokens from Github Actions
	GithubWorkflowRepository string // OID 1.3.6.1.4.1.57264.1.5

	// Git Ref of the Github Actions Workflow. Matches the `ref` claim of the ID tokens
	// from Github Actions
	GithubWorkflowRef string // 1.3.6.1.4.1.57264.1.6
}

func (e Extensions) Render() ([]pkix.Extension, error) {
	var exts []pkix.Extension

	if e.Issuer != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte(e.Issuer),
		})
	} else {
		return nil, errors.New("x509ca: extensions must have a non-empty issuer url")
	}
	if e.GithubWorkflowTrigger != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2},
			Value: []byte(e.GithubWorkflowTrigger),
		})
	}
	if e.GithubWorkflowSHA != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3},
			Value: []byte(e.GithubWorkflowSHA),
		})
	}
	if e.GithubWorkflowName != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4},
			Value: []byte(e.GithubWorkflowName),
		})
	}
	if e.GithubWorkflowRepository != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5},
			Value: []byte(e.GithubWorkflowRepository),
		})
	}
	if e.GithubWorkflowRef != "" {
		exts = append(exts, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6},
			Value: []byte(e.GithubWorkflowRef),
		})
	}
	return exts, nil
}
