// Copyright 2024 The Sigstore Authors.
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

package ciprovider

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

func claimsToString(claims map[string]interface{}) map[string]string {
	stringClaims := make(map[string]string)
	for k, v := range claims {
		stringClaims[k] = v.(string)
	}
	return stringClaims
}

// It makes string interpolation for a given string by using the
// templates syntax https://pkg.go.dev/text/template
func applyTemplateOrReplace(path string, data map[string]string, defaultData map[string]string) string {

	// Here we merge the data from was claimed by the id token with the
	// default data provided by the yaml file.
	// The order here matter because we want to override the default data
	// with the claimed data.
	mergedData := make(map[string]string)
	for k, v := range defaultData {
		mergedData[k] = v
	}
	for k, v := range data {
		mergedData[k] = v
	}

	if strings.Contains(path, "{{") {
		var doc bytes.Buffer
		t := template.New("")
		p, err := t.Parse(path)
		if err != nil {
			panic(err)
		}
		err = p.Execute(&doc, mergedData)
		if err != nil {
			panic(err)
		}
		return doc.String()
	}
	return mergedData[path]
}

type Config struct {
	Token    *oidc.IDToken
	Metadata config.IssuersMetadata
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	cfg := config.FromContext(ctx)
	issuer, ok := cfg.GetIssuer(token.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", token.Issuer)
	}

	return Config{
		token,
		cfg.IssuersMetadata[issuer.SubType],
	}, nil
}

func (p Config) Name(_ context.Context) string {
	return p.Token.Subject
}

func (p Config) Embed(_ context.Context, cert *x509.Certificate) error {

	e := p.Metadata.ClaimsMapper
	defaults := p.Metadata.Defaults

	var rawClaims map[string]interface{}
	if err := p.Token.Claims(&rawClaims); err != nil {
		return err
	}
	claims := claimsToString(rawClaims)

	subjectAlternativeNameURL, err := url.Parse(applyTemplateOrReplace(p.Metadata.SubjectAlternativeName, claims, defaults))
	if err != nil {
		panic(err)
	}
	uris := []*url.URL{subjectAlternativeNameURL}
	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = uris

	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                              applyTemplateOrReplace(e.Issuer, claims, defaults),
		GithubWorkflowTrigger:               applyTemplateOrReplace(e.GithubWorkflowTrigger, claims, defaults),
		GithubWorkflowSHA:                   applyTemplateOrReplace(e.GithubWorkflowSHA, claims, defaults),
		GithubWorkflowName:                  applyTemplateOrReplace(e.GithubWorkflowName, claims, defaults),
		GithubWorkflowRepository:            applyTemplateOrReplace(e.GithubWorkflowRepository, claims, defaults),
		GithubWorkflowRef:                   applyTemplateOrReplace(e.GithubWorkflowRef, claims, defaults),
		BuildSignerURI:                      applyTemplateOrReplace(e.BuildSignerURI, claims, defaults),
		BuildConfigDigest:                   applyTemplateOrReplace(e.BuildConfigDigest, claims, defaults),
		RunnerEnvironment:                   applyTemplateOrReplace(e.RunnerEnvironment, claims, defaults),
		SourceRepositoryURI:                 applyTemplateOrReplace(e.SourceRepositoryURI, claims, defaults),
		SourceRepositoryDigest:              applyTemplateOrReplace(e.SourceRepositoryDigest, claims, defaults),
		SourceRepositoryRef:                 applyTemplateOrReplace(e.SourceRepositoryRef, claims, defaults),
		SourceRepositoryIdentifier:          applyTemplateOrReplace(e.SourceRepositoryIdentifier, claims, defaults),
		SourceRepositoryOwnerURI:            applyTemplateOrReplace(e.SourceRepositoryOwnerURI, claims, defaults),
		SourceRepositoryOwnerIdentifier:     applyTemplateOrReplace(e.SourceRepositoryOwnerIdentifier, claims, defaults),
		BuildConfigURI:                      applyTemplateOrReplace(e.BuildConfigURI, claims, defaults),
		BuildSignerDigest:                   applyTemplateOrReplace(e.BuildSignerDigest, claims, defaults),
		BuildTrigger:                        applyTemplateOrReplace(e.BuildTrigger, claims, defaults),
		RunInvocationURI:                    applyTemplateOrReplace(e.RunInvocationURI, claims, defaults),
		SourceRepositoryVisibilityAtSigning: applyTemplateOrReplace(e.SourceRepositoryVisibilityAtSigning, claims, defaults),
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
