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

	// URL of issuer
	url string

	// Commit SHA being built
	sha string

	// Event that triggered this workflow run. E.g "push", "tag"
	eventName string

	// Name of repository being built
	repository string

	// Deprecated
	// Name of workflow that is running (mutable)
	workflow string

	// Git ref being built
	ref string

	// Specific build instructions (i.e. reusable workflow)
	jobWorkflowRef string

	// Commit SHA to specific build instructions
	jobWorkflowSha string

	// Whether the build took place in cloud or self-hosted infrastructure
	runnerEnvironment string

	// ID to the source repo
	repositoryID string

	// Owner of the source repo (mutable)
	repositoryOwner string

	// ID of the source repo
	repositoryOwnerID string

	// Ref of top-level workflow that is running
	workflowRef string

	// Commit SHA of top-level workflow that is running
	workflowSha string

	// ID of workflow run
	runID string

	// Attempt number of workflow run
	runAttempt string
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		JobWorkflowRef    string `json:"job_workflow_ref"`
		Sha               string `json:"sha"`
		EventName         string `json:"event_name"`
		Repository        string `json:"repository"`
		Workflow          string `json:"workflow"`
		Ref               string `json:"ref"`
		JobWorkflowSha    string `json:"job_workflow_sha"`
		RunnerEnvironment string `json:"runner_environment"`
		RepositoryID      string `json:"repository_id"`
		RepositoryOwner   string `json:"repository_owner"`
		RepositoryOwnerID string `json:"repository_owner_id"`
		WorkflowRef       string `json:"workflow_ref"`
		WorkflowSha       string `json:"workflow_sha"`
		RunID             string `json:"run_id"`
		RunAttempt        string `json:"run_attempt"`
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
	if claims.EventName == "" {
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
	if claims.JobWorkflowSha == "" {
		return nil, errors.New("missing job_workflow_sha claim in ID token")
	}
	if claims.RunnerEnvironment == "" {
		return nil, errors.New("missing runner_environment claim in ID token")
	}
	if claims.RepositoryID == "" {
		return nil, errors.New("missing repository_id claim in ID token")
	}
	if claims.RepositoryOwner == "" {
		return nil, errors.New("missing repository_owner claim in ID token")
	}
	if claims.RepositoryOwnerID == "" {
		return nil, errors.New("missing repository_owner_id claim in ID token")
	}
	if claims.WorkflowRef == "" {
		return nil, errors.New("missing workflow_ref claim in ID token")
	}
	if claims.WorkflowSha == "" {
		return nil, errors.New("missing workflow_sha claim in ID token")
	}
	if claims.RunID == "" {
		return nil, errors.New("missing run_id claim in ID token")
	}
	if claims.RunAttempt == "" {
		return nil, errors.New("missing run_attempt claim in ID token")
	}

	return &workflowPrincipal{
		subject:           token.Subject,
		issuer:            token.Issuer,
		url:               `https://github.com/`,
		sha:               claims.Sha,
		eventName:         claims.EventName,
		repository:        claims.Repository,
		workflow:          claims.Workflow,
		ref:               claims.Ref,
		jobWorkflowRef:    claims.JobWorkflowRef,
		jobWorkflowSha:    claims.JobWorkflowSha,
		runnerEnvironment: claims.RunnerEnvironment,
		repositoryID:      claims.RepositoryID,
		repositoryOwner:   claims.RepositoryOwner,
		repositoryOwnerID: claims.RepositoryOwnerID,
		workflowRef:       claims.WorkflowRef,
		workflowSha:       claims.WorkflowSha,
		runID:             claims.RunID,
		runAttempt:        claims.RunAttempt,
	}, nil
}

func (w workflowPrincipal) Name(ctx context.Context) string {
	return w.subject
}

func (w workflowPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	baseURL, err := url.Parse(w.url)
	if err != nil {
		return err
	}

	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = []*url.URL{baseURL.JoinPath(w.jobWorkflowRef)}

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: w.issuer,
		// BEGIN: Deprecated
		GithubWorkflowTrigger:    w.eventName,
		GithubWorkflowSHA:        w.sha,
		GithubWorkflowName:       w.workflow,
		GithubWorkflowRepository: w.repository,
		GithubWorkflowRef:        w.ref,
		// END: Deprecated

		BuildSignerURI:                  baseURL.JoinPath(w.jobWorkflowRef).String(),
		BuildSignerDigest:               w.jobWorkflowSha,
		RunnerEnvironment:               w.runnerEnvironment,
		SourceRepositoryURI:             baseURL.JoinPath(w.repository).String(),
		SourceRepositoryDigest:          w.sha,
		SourceRepositoryRef:             w.ref,
		SourceRepositoryIdentifier:      w.repositoryID,
		SourceRepositoryOwnerURI:        baseURL.JoinPath(w.repositoryOwner).String(),
		SourceRepositoryOwnerIdentifier: w.repositoryOwnerID,
		BuildConfigURI:                  baseURL.JoinPath(w.workflowRef).String(),
		BuildConfigDigest:               w.workflowSha,
		BuildTrigger:                    w.eventName,
		RunInvocationURI:                baseURL.JoinPath(w.repository, "actions/runs", w.runID, "attempts", w.runAttempt).String(),
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
