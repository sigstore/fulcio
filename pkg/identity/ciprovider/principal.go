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
	"context"
	"crypto/x509"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

type Provider struct {
	Subject     string
	Extensions  certificate.Extensions
	Uris        []string
	Defaults    map[string]string
	OIDCIssuers []config.OIDCIssuer `yaml:"oidc-issuers,omitempty"`
}

// TO BE IMPLEMENTED. Just kept as a guide
func WorkflowPrincipalFromIDToken(_ context.Context, _ *oidc.IDToken) (identity.Principal, error) {
	return nil, nil
}

// TO BE IMPLEMENTED. Just kept as a guide
func (Provider) Name(_ context.Context) string {
	return ""
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
