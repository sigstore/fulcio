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
	"github.com/fatih/structs"
	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

func mapValuesToString(claims map[string]interface{}) map[string]string {
	stringClaims := make(map[string]string)
	for k, v := range claims {
		stringClaims[k] = v.(string)
	}
	return stringClaims
}

// It makes string interpolation for a given string by using the
// templates syntax https://pkg.go.dev/text/template
func applyTemplateOrReplace(extValueTemplate string, tokenClaims map[string]string, defaultTemplateValues map[string]string) (string, error) {

	// Here we merge the data from was claimed by the id token with the
	// default data provided by the yaml file.
	// The order here matter because we want to override the claimed data
	// with the default data.
	// The default data will have priority over the claimed data.
	mergedData := make(map[string]string)
	for k, v := range tokenClaims {
		mergedData[k] = v
	}
	for k, v := range defaultTemplateValues {
		mergedData[k] = v
	}

	if strings.Contains(extValueTemplate, "{{") {
		var doc bytes.Buffer
		// This option forces to having the claim that is required
		// for the template
		t := template.New("").Option("missingkey=error")
		p, err := t.Parse(extValueTemplate)
		if err != nil {
			return "", err
		}
		err = p.Execute(&doc, mergedData)
		if err != nil {
			return "", err
		}
		return doc.String(), nil
	}
	claimValue, ok := mergedData[extValueTemplate]
	if !ok {
		return "", fmt.Errorf("value <%s> not present in either claims or defaults", extValueTemplate)
	}
	return claimValue, nil
}

type Config struct {
	Token    *oidc.IDToken
	Metadata config.DefaultTemplateValues
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	cfg := config.FromContext(ctx)
	issuer, ok := cfg.GetIssuer(token.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", token.Issuer)
	}

	return Config{
		token,
		cfg.CIIssuerMetadata[issuer.CIProvider],
	}, nil
}

func (p Config) Name(_ context.Context) string {
	return p.Token.Subject
}

func (p Config) Embed(_ context.Context, cert *x509.Certificate) error {

	e := p.Metadata.ClaimsMap
	defaults := p.Metadata.Defaults

	var rawClaims map[string]interface{}
	if err := p.Token.Claims(&rawClaims); err != nil {
		return err
	}
	claims := mapValuesToString(rawClaims)

	subjectAlternativeName, err := applyTemplateOrReplace(p.Metadata.SubjectAlternativeName, claims, defaults)
	if err != nil {
		return err
	}
	subjectAlternativeNameURL, err := url.Parse(subjectAlternativeName)
	if err != nil {
		return err
	}
	uris := []*url.URL{subjectAlternativeNameURL}
	// Set workflow ref URL to SubjectAlternativeName on certificate
	cert.URIs = uris
	mapExtensionsForTemplate := mapValuesToString(structs.Map(e))
	for k, v := range mapExtensionsForTemplate {
		mapExtensionsForTemplate[k], err = applyTemplateOrReplace(v, claims, defaults)
		if err != nil {
			return err
		}
	}
	ext := &certificate.Extensions{}
	err = mapstructure.Decode(mapExtensionsForTemplate, &ext)
	if err != nil {
		return err
	}
	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = ext.Render()
	if err != nil {
		return err
	}

	return nil
}
