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

package buildkite

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"

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

	// Buildkite's domain
	url string

	// Unique identifier for a Buildkite customer
	organizationSlug string

	// Unique identifier (within the scope of an OrganizationSlug) for a container of many builds.
	pipelineSlug string

	// Incrementing number within each pipeline
	buildNumber int64

	// The commit sha being tested by a build
	buildCommit string

	// UUID that identifies a single unique execution within a build
	jobId string

	// Did the job run in a cloud hosted environment or self hosted by the customer. All
	// Buildkite jobs execute on self hosted agents, so this will always be `self-hosted`
	runnerEnvironment string
}

func JobPrincipalFromIDToken(_ context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		OrganizationSlug string      `json:"organization_slug"`
		PipelineSlug     string      `json:"pipeline_slug"`
		BuildNumber      json.Number `json:"build_number"`
		BuildCommit      string      `json:"build_commit"`
		JobId            string      `json:"job_id"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	if claims.OrganizationSlug == "" {
		return nil, errors.New("missing organization_slug claim in ID token")
	}

	if claims.PipelineSlug == "" {
		return nil, errors.New("missing pipeline_slug claim in ID token")
	}

	buildNumber, err := claims.BuildNumber.Int64()
	if err != nil {
		return nil, errors.New("error parsing build_number claim in ID token")
	}

	if claims.BuildCommit == "" {
		return nil, errors.New("missing build_commit claim in ID token")
	}

	if claims.JobId == "" {
		return nil, errors.New("missing job_id claim in ID token")
	}

	return &jobPrincipal{
		subject:           token.Subject,
		issuer:            token.Issuer,
		url:               "https://buildkite.com",
		organizationSlug:  claims.OrganizationSlug,
		pipelineSlug:      claims.PipelineSlug,
		buildNumber:       buildNumber,
		buildCommit:       claims.BuildCommit,
		jobId:             claims.JobId,
		runnerEnvironment: "self-hosted",
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

	pipelineUrl := baseURL.JoinPath(p.organizationSlug, p.pipelineSlug)
	jobUrl := baseURL.JoinPath(p.organizationSlug, p.pipelineSlug, "builds", strconv.FormatInt(p.buildNumber, 10)+"#"+p.jobId)

	// Set SubjectAlternativeName to the pipeline URL on the certificate
	cert.URIs = []*url.URL{pipelineUrl}

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                 p.issuer,
		RunInvocationURI:       jobUrl.String(),
		RunnerEnvironment:      p.runnerEnvironment,
		SourceRepositoryDigest: p.buildCommit,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
