// Copyright 2021 The Sigstore Authors.
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

package spiffe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type principal struct {
	// spiffe ID
	id string

	// OIDC issuer url
	issuer string
}

func PrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	cfg, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	if err := validSpiffeID(token.Subject, cfg.SPIFFETrustDomain); err != nil {
		return nil, err
	}

	return principal{
		id:     token.Subject,
		issuer: token.Issuer,
	}, nil

}

func validSpiffeID(id, trustDomain string) error {
	parsedTrustDomain, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return fmt.Errorf("unable to parse trust domain from configuration %s: %w", trustDomain, err)
	}

	parsedID, err := spiffeid.FromString(id)
	if err != nil {
		return fmt.Errorf("invalid spiffe ID provided: %s", id)
	}

	if parsedID.TrustDomain().Compare(parsedTrustDomain) != 0 {
		return fmt.Errorf("spiffe ID trust domain %s doesn't match configured trust domain %s", parsedID.TrustDomain(), trustDomain)
	}

	return nil
}

func (p principal) Name(context.Context) string {
	return p.id
}

func (p principal) Embed(ctx context.Context, cert *x509.Certificate) error {
	parsed, err := url.Parse(p.id)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{parsed}

	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: p.issuer,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
