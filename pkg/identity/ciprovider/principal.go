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
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/log"
)

func mapValuesToString(claims map[string]any) map[string]string {
	newMap := make(map[string]string)
	for k, v := range claims {
		vType := reflect.ValueOf(v)
		switch vType.Kind() {
		case reflect.Float32, reflect.Float64:
			value := vType.Interface().(float64)
			if value == math.Trunc(value) {
				// A float, but with no fractional part. Treat as an int
				newMap[k] = fmt.Sprintf("%v", math.Trunc(value))
			} else {
				newMap[k] = strconv.FormatFloat(value, 'f', -1, 64)
			}
		default:
			newMap[k] = fmt.Sprintf("%v", v)
		}
	}
	return newMap
}

func getTokenClaims(token *oidc.IDToken) (map[string]string, error) {
	var tokenClaims map[string]any
	if err := token.Claims(&tokenClaims); err != nil {
		return nil, err
	}
	return mapValuesToString(tokenClaims), nil
}

// applyTemplateOrReplace performs string interpolation on a given template string.
// It uses Go's text/template syntax (https://pkg.go.dev/text/template).
// The logMetadata parameter is included to provide richer log messages.
func applyTemplateOrReplace(
	extValueTemplate string, tokenClaims map[string]string,
	issuerMetadata map[string]string, logMetadata map[string]string) (string, error) {

	// Merge the data from the ID token claims with the default data
	// from the issuer's metadata configuration.
	// The order of maps.Copy is important here. We copy tokenClaims last
	// to ensure that claim data takes priority over the default metadata.
	mergedData := make(map[string]string)
	maps.Copy(mergedData, issuerMetadata)
	maps.Copy(mergedData, tokenClaims)

	if strings.Contains(extValueTemplate, "{{") {
		var doc bytes.Buffer
		// The "missingkey=error" option ensures that if a claim referenced
		// in the template is not present in the merged data, template
		// execution will fail.
		t := template.New("").Option("missingkey=error")
		// It shouldn't raise error since we already checked all
		// templates in validateCIIssuerMetadata functions in config.go
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
		var jsonMetadata bytes.Buffer
		inrec, _ := json.Marshal(logMetadata)
		_ = json.Indent(&jsonMetadata, inrec, "", "\t")
		return "", fmt.Errorf("value <%s> not present in either claims or defaults. %s", extValueTemplate, jsonMetadata.String())
	}
	return claimValue, nil
}

type ciPrincipal struct {
	Token          *oidc.IDToken
	ClaimsMetadata config.IssuerMetadata
}

func WorkflowPrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	cfg := config.FromContext(ctx)
	issuerCfg, ok := cfg.GetIssuer(token.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", token.Issuer)
	}
	metadata, ok := cfg.CIIssuerMetadata[issuerCfg.CIProvider]
	if !ok {
		return nil, fmt.Errorf(
			"metadata not found for ci provider %s, issuer: %s", issuerCfg.CIProvider, token.Issuer)
	}
	return ciPrincipal{
		token,
		metadata,
	}, nil
}

func (principal ciPrincipal) Name(_ context.Context) string {
	return principal.Token.Subject
}

func (principal ciPrincipal) Embed(_ context.Context, cert *x509.Certificate) error {

	claimsTemplates := principal.ClaimsMetadata.ExtensionTemplates
	defaults := principal.ClaimsMetadata.DefaultTemplateValues
	claims, err := getTokenClaims(principal.Token)
	if err != nil {
		return err
	}
	if strings.TrimSpace(principal.ClaimsMetadata.SubjectAlternativeNameTemplate) == "" {
		return fmt.Errorf("SubjectAlternativeNameTemplate should not be empty. Issuer: %s", principal.Token.Issuer)
	}
	subjectAlternativeName, err := applyTemplateOrReplace(
		principal.ClaimsMetadata.SubjectAlternativeNameTemplate, claims, defaults,
		map[string]string{
			"Issuer":        principal.Token.Issuer,
			"ExtensionName": "SubjectAlternativeName",
		})
	if err != nil {
		log.Logger.Errorf("error applying template with claims %v and defaults %v: %v", claims, defaults, err)
		return err
	}
	sanURL, err := url.Parse(subjectAlternativeName)
	if err != nil {
		return err
	}
	uris := []*url.URL{sanURL}
	cert.URIs = uris
	// We use value.Elem() here because we need an addressable
	// reference to the template fields to modify them with SetString().
	v := reflect.ValueOf(&claimsTemplates).Elem()
	// The type of the reflect value is needed to get the field name
	// for logging and for checking against the "Issuer" field.
	vType := v.Type()
	for i := range v.NumField() {
		s := v.Field(i).String() // value of each field, e.g the template string
		// We check the field name to avoid applying the template for the Issuer.
		// The Issuer field should always come from the token issuer.
		if strings.TrimSpace(s) == "" || vType.Field(i).Name == "Issuer" {
			continue
		}
		extValue, err := applyTemplateOrReplace(s, claims, defaults,
			map[string]string{
				"Issuer":        principal.Token.Issuer,
				"ExtensionName": vType.Field(i).Name,
			})
		if err != nil {
			return err
		}
		v.Field(i).SetString(extValue)
	}

	// Guarantee that the extension issuer is set to the token issuer,
	// regardless of whether this field has been set before
	claimsTemplates.Issuer = principal.Token.Issuer
	// Embed additional information into custom extensions
	cert.ExtraExtensions, err = claimsTemplates.Render()
	if err != nil {
		return err
	}
	return nil
}
