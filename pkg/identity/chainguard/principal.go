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
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

type workflowPrincipal struct {
	issuer  string
	subject string
	name    string

	actor            map[string]string
	servicePrincipal string
}

var _ identity.Principal = (*workflowPrincipal)(nil)

func (w workflowPrincipal) Name(_ context.Context) string {
	return w.name
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

	// This is the exact function that cosign uses to extract the "subject"
	// (misnomer) from the token in order to establish "proof of possession".
	// We MUST use this to implement Name() or tokens that embed an email claim
	// will fail to sign because of this divergent logic.
	name, err := oauthflow.SubjectFromToken(token)
	if err != nil {
		return nil, err
	}

	return &workflowPrincipal{
		issuer:           token.Issuer,
		subject:          token.Subject,
		name:             name,
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
