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

package github

import (
	"context"
	"crypto/x509"
	"net/url"

	"github.com/sigstore/fulcio/pkg/ca/x509ca"
)

const issuerURL = `https://token.actions.githubusercontent.com`

type workflowPrincipal struct {
	// Full URL to workflow
	url string

	sha        string
	trigger    string
	repository string
	workflow   string
	ref        string
}

func (w workflowPrincipal) Name(ctx context.Context) string {
	return w.url
}

func (w workflowPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	// Set workflow URL to SubjectNameAlt on certificate
	parsed, err := url.Parse(w.url)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{parsed}

	// Embed additional information into customer extensions
	cert.ExtraExtensions, err = x509ca.Extensions{
		Issuer:                   issuerURL,
		GithubWorkflowTrigger:    w.trigger,
		GithubWorkflowSHA:        w.sha,
		GithubWorkflowName:       w.workflow,
		GithubWorkflowRepository: w.repository,
		GithubWorkflowRef:        w.ref,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
