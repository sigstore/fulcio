// Copyright 2023 The Sigstore Authors.
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

package gitlabcom

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/identity"
)

type jobPrincipal struct {
	// Subject matches the 'sub' claim from the OIDC ID token this is what is
	// signed as proof of possession for Buildkite job identities
	subject string

	// OIDC Issuer URL. Matches 'iss' claim from ID token. The real issuer URL is
	// https://agent.buildkite.com/.well-known/openid-configuration
	issuer string

	// The URL of the GitLab instance. https://gitlab.com
	url string

	// Event that triggered this workflow run. E.g "push", "tag" etc
	eventName string

	// Pipeline ID
	pipelineID string

	// Ref of top-level pipeline definition. E.g. gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main
	ciConfigRefURI string

	// Commit sha of top-level pipeline definition, and is
	// only populated when `ciConfigRefURI` is local to the GitLab instance
	ciConfigSha string

	// Repository building built
	repository string

	// ID to the source repo
	repositoryID string

	// Owner of the source repo (mutable)
	repositoryOwner string

	// ID of the source repo
	repositoryOwnerID string

	// job ID
	jobID string

	// Git ref being built
	ref string

	// Commit SHA being built
	sha string

	// ID of the runner
	runnerID int64

	// The type of runner used by the job. May be one of gitlab-hosted or self-hosted.
	runnerEnvironment string
}

func JobPrincipalFromIDToken(_ context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		ProjectPath       string `json:"project_path"`
		ProjectID         string `json:"project_id"`
		PipelineSource    string `json:"pipeline_source"`
		PipelineID        string `json:"pipeline_id"`
		CiConfigRefURI    string `json:"ci_config_ref_uri"`
		CiConfigSha       string `json:"ci_config_sha"`
		NamespacePath     string `json:"namespace_path"`
		NamespaceID       string `json:"namespace_id"`
		JobID             string `json:"job_id"`
		Ref               string `json:"ref"`
		RefType           string `json:"ref_type"`
		Sha               string `json:"sha"`
		RunnerEnvironment string `json:"runner_environment"`
		RunnerID          int64  `json:"runner_id"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	if claims.ProjectPath == "" {
		return nil, errors.New("missing project_path claim in ID token")
	}

	if claims.PipelineSource == "" {
		return nil, errors.New("missing pipeline_source claim in ID token")
	}

	if claims.PipelineID == "" {
		return nil, errors.New("missing pipeline_id claim in ID token")
	}

	if claims.CiConfigRefURI == "" {
		return nil, errors.New("missing ci_config_ref_uri claim in ID token")
	}

	if claims.JobID == "" {
		return nil, errors.New("missing job_id claim in ID token")
	}

	if claims.Ref == "" {
		return nil, errors.New("missing ref claim in ID token")
	}

	if claims.RefType == "" {
		return nil, errors.New("missing ref_type claim in ID token")
	}

	if claims.NamespacePath == "" {
		return nil, errors.New("missing namespace_path claim in ID token")
	}

	if claims.NamespaceID == "" {
		return nil, errors.New("missing namespace_id claim in ID token")
	}

	if claims.ProjectID == "" {
		return nil, errors.New("missing project_id claim in ID token")
	}

	if claims.Sha == "" {
		return nil, errors.New("missing sha claim in ID token")
	}

	if claims.RunnerEnvironment == "" {
		return nil, errors.New("missing runner_environment claim in ID token")
	}

	if claims.RunnerID == 0 {
		return nil, errors.New("missing runner_id claim in ID token")
	}

	var ref string
	switch claims.RefType {
	case "branch":
		ref = "refs/heads/" + claims.Ref
	case "tag":
		ref = "refs/tags/" + claims.Ref
	default:
		return nil, fmt.Errorf("unexpected ref_type: %s", claims.RefType)
	}

	return &jobPrincipal{
		subject:           token.Subject,
		issuer:            token.Issuer,
		url:               `https://gitlab.com/`,
		eventName:         claims.PipelineSource,
		pipelineID:        claims.PipelineID,
		ciConfigRefURI:    claims.CiConfigRefURI,
		ciConfigSha:       claims.CiConfigSha,
		repository:        claims.ProjectPath,
		ref:               ref,
		repositoryID:      claims.ProjectID,
		repositoryOwner:   claims.NamespacePath,
		repositoryOwnerID: claims.NamespaceID,
		jobID:             claims.JobID,
		sha:               claims.Sha,
		runnerID:          claims.RunnerID,
		runnerEnvironment: claims.RunnerEnvironment,
	}, nil
}

func (p jobPrincipal) Name(_ context.Context) string {
	return p.subject
}

func (p jobPrincipal) Embed(_ context.Context, cert *x509.Certificate) error {
	baseURL, err := url.Parse(p.url)
	if err != nil {
		return err
	}

	// pipeline_ref claim is a URI that does not include protocol scheme so we need to normalize it
	ciConfigRefURL, err := url.Parse(p.ciConfigRefURI)
	if err != nil {
		return err
	}

	// default to https
	ciConfigRefURL.Scheme = "https"

	// or use scheme from issuer if from the same host
	if baseURL.Host == ciConfigRefURL.Host {
		ciConfigRefURL.Scheme = baseURL.Scheme
	}

	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = []*url.URL{ciConfigRefURL}

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                          p.issuer,
		BuildConfigURI:                  ciConfigRefURL.String(),
		BuildConfigDigest:               p.ciConfigSha,
		BuildSignerURI:                  ciConfigRefURL.String(),
		BuildSignerDigest:               p.ciConfigSha,
		RunnerEnvironment:               p.runnerEnvironment,
		SourceRepositoryURI:             baseURL.JoinPath(p.repository).String(),
		SourceRepositoryDigest:          p.sha,
		SourceRepositoryRef:             p.ref,
		SourceRepositoryIdentifier:      p.repositoryID,
		SourceRepositoryOwnerURI:        baseURL.JoinPath(p.repositoryOwner).String(),
		SourceRepositoryOwnerIdentifier: p.repositoryOwnerID,
		BuildTrigger:                    p.eventName,
		RunInvocationURI:                baseURL.JoinPath(p.repository, "/-/jobs/", p.jobID).String(),
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
