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

package email

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/asaskevich/govalidator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/oauthflow"
)

type principal struct {
	address string
	issuer  string
}

func PrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(token)
	if err != nil {
		return nil, err
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	// Check email_verified claim unless the issuer is configured to skip verification
	if !cfg.SkipEmailVerification && !emailVerified {
		return nil, errors.New("email_verified claim was false")
	}

	if !govalidator.IsEmail(emailAddress) {
		return nil, fmt.Errorf("email address is not valid")
	}

	issuer, err := oauthflow.IssuerFromIDToken(token, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return principal{
		issuer:  issuer,
		address: emailAddress,
	}, nil
}

func (p principal) Name(_ context.Context) string {
	return p.address
}

func (p principal) Embed(_ context.Context, cert *x509.Certificate) error {
	cert.EmailAddresses = []string{p.address}

	var err error
	cert.ExtraExtensions, err = certificate.Extensions{
		Issuer: p.issuer,
	}.Render()
	if err != nil {
		return err
	}

	return nil
}
