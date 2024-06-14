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
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Providers map[config.IssuerType]Provider
}
type Provider struct {
	Subject     string
	Extensions  certificate.Extensions
	Uris        []string
	Defaults    map[string]string
	OIDCIssuers []config.OIDCIssuer `yaml:"oidc-issuers,omitempty"`
	MetaIssuers []config.OIDCIssuer `yaml:"meta-issuers,omitempty"`
	Claims      map[string]interface{}
}

func readConfig() Config {
	var obj Config

	configFile, err := os.ReadFile("providers_config.yaml")
	if err != nil {
		fmt.Printf("yamlFile.Get err #%v ", err)
	}
	err = yaml.Unmarshal(configFile, &obj)
	if err != nil {
		fmt.Printf("Unmarshal: %v", err)
	}

	return obj
}

func claimsToString(claims map[string]interface{}) map[string]string {
	stringClaims := make(map[string]string)
	for k, v := range claims {
		stringClaims[k] = v.(string)
	}
	return stringClaims
}

func ApplyTemplate(path string, data map[string]string, defaultData map[string]string) string {

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

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	iss, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", token.Issuer)
	}
	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	configYaml := readConfig()
	provider := configYaml.Providers[iss.Type]
	provider.Claims = claims
	provider.Subject = token.Subject
	return provider, nil
}

func (p Provider) Name(_ context.Context) string {
	return p.Subject
}

func (p Provider) Embed(_ context.Context, cert *x509.Certificate) error {

	e := p.Extensions
	defaults := p.Defaults
	claims := claimsToString(p.Claims)
	uris := make([]*url.URL, len(p.Uris))
	for _, value := range p.Uris {
		url, err := url.Parse(ApplyTemplate(value, claims, defaults))
		if err != nil {
			panic(err)
		}
		uris = append(uris, url)
	}
	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = uris

	var err error
	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer:                              ApplyTemplate(e.Issuer, claims, defaults),
		GithubWorkflowTrigger:               ApplyTemplate(e.GithubWorkflowTrigger, claims, defaults),
		GithubWorkflowSHA:                   ApplyTemplate(e.GithubWorkflowSHA, claims, defaults),
		GithubWorkflowName:                  ApplyTemplate(e.GithubWorkflowName, claims, defaults),
		GithubWorkflowRepository:            ApplyTemplate(e.GithubWorkflowRepository, claims, defaults),
		GithubWorkflowRef:                   ApplyTemplate(e.GithubWorkflowRef, claims, defaults),
		BuildSignerURI:                      ApplyTemplate(e.BuildSignerURI, claims, defaults),
		BuildConfigDigest:                   ApplyTemplate(e.BuildConfigDigest, claims, defaults),
		RunnerEnvironment:                   ApplyTemplate(e.RunnerEnvironment, claims, defaults),
		SourceRepositoryURI:                 ApplyTemplate(e.SourceRepositoryURI, claims, defaults),
		SourceRepositoryDigest:              ApplyTemplate(e.SourceRepositoryDigest, claims, defaults),
		SourceRepositoryRef:                 ApplyTemplate(e.SourceRepositoryRef, claims, defaults),
		SourceRepositoryIdentifier:          ApplyTemplate(e.SourceRepositoryIdentifier, claims, defaults),
		SourceRepositoryOwnerURI:            ApplyTemplate(e.SourceRepositoryOwnerURI, claims, defaults),
		SourceRepositoryOwnerIdentifier:     ApplyTemplate(e.SourceRepositoryOwnerIdentifier, claims, defaults),
		BuildConfigURI:                      ApplyTemplate(e.BuildConfigURI, claims, defaults),
		BuildSignerDigest:                   ApplyTemplate(e.BuildSignerDigest, claims, defaults),
		BuildTrigger:                        ApplyTemplate(e.BuildTrigger, claims, defaults),
		RunInvocationURI:                    ApplyTemplate(e.RunInvocationURI, claims, defaults),
		SourceRepositoryVisibilityAtSigning: ApplyTemplate(e.SourceRepositoryVisibilityAtSigning, claims, defaults),
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
