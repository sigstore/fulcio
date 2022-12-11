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
	"errors"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/identity"
)

type workflowPrincipal struct {
	// Subject matches the 'sub' claim from the OIDC ID token this is what is
	// signed as proof of possession for Github workflow identities
	subject string

	// OIDC Issuer URL. Matches 'iss' claim from ID token. The real issuer URL is
	// https://token.actions.githubusercontent.com/.well-known/openid-configution
	issuer string

	// the final certificate.
	url string

	// Commit SHA being built
	sha string

	// Event that triggered this workflow run. E.g "push", "tag" etc
	trigger string

	// Repository building built
	repository string

	// Workflow that is running
	workflow string

	// Git ref being built
	ref string
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		JobWorkflowRef string `json:"job_workflow_ref"`
		Sha            string `json:"sha"`
		Trigger        string `json:"event_name"`
		Repository     string `json:"repository"`
		Workflow       string `json:"workflow"`
		Ref            string `json:"ref"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	if claims.JobWorkflowRef == "" {
		return nil, errors.New("missing job_workflow_ref claim in ID token")
	}
	if claims.Sha == "" {
		return nil, errors.New("missing sha claim in ID token")
	}
	if claims.Trigger == "" {
		return nil, errors.New("missing event_name claim in ID token")
	}
	if claims.Repository == "" {
		return nil, errors.New("missing repository claim in ID token")
	}
	if claims.Workflow == "" {
		return nil, errors.New("missing workflow claim in ID token")
	}
	if claims.Ref == "" {
		return nil, errors.New("missing ref claim in ID token")
	}

	return &workflowPrincipal{
		subject:    token.Subject,
		issuer:     token.Issuer,
		url:        `https://github.com/` + claims.JobWorkflowRef,
		sha:        claims.Sha,
		trigger:    claims.Trigger,
		repository: claims.Repository,
		workflow:   claims.Workflow,
		ref:        claims.Ref,
	}, nil
}

func (w workflowPrincipal) Name(ctx context.Context) string {
	return w.subject
}

func (w workflowPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	// Set workflow URL to SubjectAlternativeName on certificate
	parsed, err := url.Parse(w.url)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{parsed}

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                   w.issuer,
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
