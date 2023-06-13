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

package uri

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/asaskevich/govalidator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

type principal struct {
	issuer string
	uri    string
}

func PrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	uriWithSubject := token.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	if govalidator.IsEmail(uriWithSubject) {
		return nil, fmt.Errorf("uri subject should not be an email address")
	}

	// The subject hostname must exactly match the subject domain from the configuration
	uSubject, err := url.Parse(uriWithSubject)
	if err != nil {
		return nil, err
	}
	uDomain, err := url.Parse(cfg.SubjectDomain)
	if err != nil {
		return nil, err
	}
	if uSubject.Scheme != uDomain.Scheme {
		return nil, fmt.Errorf("subject URI scheme (%s) must match expected domain URI scheme (%s)", uSubject.Scheme, uDomain.Scheme)
	}
	if uSubject.Hostname() != uDomain.Hostname() {
		return nil, fmt.Errorf("subject hostname (%s) must match expected domain (%s)", uSubject.Hostname(), uDomain.Hostname())
	}

	return principal{
		issuer: token.Issuer,
		uri:    uriWithSubject,
	}, nil
}

func (p principal) Name(_ context.Context) string {
	return p.uri
}

func (p principal) Embed(_ context.Context, cert *x509.Certificate) error {
	subjectURI, err := url.Parse(p.uri)
	if err != nil {
		return err
	}
	cert.URIs = []*url.URL{subjectURI}

	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: p.issuer,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
