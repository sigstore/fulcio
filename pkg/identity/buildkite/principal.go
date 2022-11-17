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

package buildkite

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
	// https://agent.buildkite.com/.well-known/openid-configution
	issuer string

	// The full URL to the job. This will be the set as SubjectAlternativeName URI in
	// the final certificate.
	url string
}

func JobPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		OrganizationSlug string `json:"organization_slug"`
		PipelineSlug     string `json:"pipeline_slug"`
		BuildNumber      int    `json:"build_number"`
		JobID            string `json:"job_id"`
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

	if claims.BuildNumber == 0 {
		return nil, errors.New("missing build_number claim in ID token")
	}

	if claims.JobID == "" {
		return nil, errors.New("missing job_id claim in ID token")
	}

	return &jobPrincipal{
		subject: token.Subject,
		issuer:  token.Issuer,
		url:     fmt.Sprintf("https://buildkite.com/%s/%s/builds/%d#%s", claims.OrganizationSlug, claims.PipelineSlug, claims.BuildNumber, claims.JobID),
	}, nil
}

func (p jobPrincipal) Name(ctx context.Context) string {
	return p.subject
}

func (p jobPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	// Set job URL to SubjectAlternativeName on certificate
	parsed, err := url.Parse(p.url)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{parsed}

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: p.issuer,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
