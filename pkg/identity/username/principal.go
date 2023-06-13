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

package username

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type principal struct {
	issuer     string
	username   string
	unIdentity string
}

func PrincipalFromIDToken(ctx context.Context, token *oidc.IDToken) (identity.Principal, error) {
	username := token.Subject

	if strings.Contains(username, "!") {
		return nil, errors.New("username cannot contain ! character")
	}

	if govalidator.IsEmail(username) {
		return nil, fmt.Errorf("uri subject should not be an email address")
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(token.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	unIdentity := fmt.Sprintf("%s!%s", username, cfg.SubjectDomain)

	return principal{
		issuer:     token.Issuer,
		username:   username,
		unIdentity: unIdentity,
	}, nil
}

func (p principal) Name(context.Context) string {
	return p.username
}

func (p principal) Embed(_ context.Context, cert *x509.Certificate) error {
	var exts []pkix.Extension

	ext, err := cryptoutils.MarshalOtherNameSAN(p.unIdentity, true /*critical*/)
	if err != nil {
		return err
	}
	exts = append(exts, *ext)

	issuerExt, err := certificate.Extensions{
		Issuer: p.issuer,
	}.Render()
	if err != nil {
		return err
	}
	exts = append(exts, issuerExt...)

	cert.ExtraExtensions = exts
	return nil
}
