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

package generic

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"gopkg.in/yaml.v3"
)

type RootYaml struct {
	Providers map[string]Provider
}

type Provider struct {
	Subject     string
	Extensions  certificate.Extensions
	Uris        []string
	Defaults    map[string]string
	OIDCIssuers []config.OIDCIssuer `yaml:"oidc-issuers,omitempty"`
}

func readYaml() RootYaml {
	var obj RootYaml

	yamlFile, err := os.ReadFile("../../config/config.yaml")
	if err != nil {
		fmt.Printf("yamlFile.Get err #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &obj)
	if err != nil {
		fmt.Printf("Unmarshal: %v", err)
	}

	return obj
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	iss, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", token.Issuer)
	}

	var claims map[string]string
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	configYaml := readYaml()

	provider := configYaml.Providers[string(iss.Type)]
	e := provider.Extensions
	defaults := provider.Defaults
	finalExtensions := certificate.Extensions{
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
	}
	finalUris := make([]string, len(provider.Uris)-1)
	for _, val := range provider.Uris {
		finalUris = append(finalUris, ApplyTemplate(val, claims, defaults))
	}

	return &Provider{
		Subject:     token.Subject,
		Extensions:  finalExtensions,
		Uris:        finalUris,
		OIDCIssuers: provider.OIDCIssuers,
	}, nil
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

	// It checks it is a path or a raw field by
	// checking exists template syntax into the string
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
	} else {
		return mergedData[path]
	}
}

func (p Provider) Name(_ context.Context) string {
	return p.Subject
}

func (p Provider) Embed(_ context.Context, cert *x509.Certificate) error {

	uris := make([]*url.URL, len(p.Uris))
	for _, value := range p.Uris {
		url, err := url.Parse(value)
		if err != nil {
			panic(err)
		}
		uris = append(uris, url)
	}
	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = uris

	var err error
	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = p.Extensions.Render()
	if err != nil {
		return err
	}

	return nil
}
