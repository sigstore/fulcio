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

package chainguard

import (
	"context"
	"crypto/x509"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/identity"
)

type workflowPrincipal struct {
	issuer  string
	subject string

	actor            map[string]string
	servicePrincipal string
}

var _ identity.Principal = (*workflowPrincipal)(nil)

func (w workflowPrincipal) Name(_ context.Context) string {
	return w.subject
}

func PrincipalFromIDToken(_ context.Context, token *oidc.IDToken) (identity.Principal, error) {
	var claims struct {
		Actor    map[string]string `json:"act"`
		Internal struct {
			ServicePrincipal string `json:"service-principal,omitempty"`
		} `json:"internal"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	return &workflowPrincipal{
		issuer:           token.Issuer,
		subject:          token.Subject,
		actor:            claims.Actor,
		servicePrincipal: claims.Internal.ServicePrincipal,
	}, nil
}

func (w workflowPrincipal) Embed(_ context.Context, cert *x509.Certificate) error {
	baseURL, err := url.Parse(w.issuer)
	if err != nil {
		return err
	}

	// Set SAN to the <issuer>/<subject>
	cert.URIs = []*url.URL{baseURL.JoinPath(w.subject)}

	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: w.issuer,

		// TODO(mattmoor): Embed more of the Chainguard token structure via OIDs.
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
