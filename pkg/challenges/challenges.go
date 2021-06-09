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
//

package challenges

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ca/googleca"

	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/oauthflow"
)

func Email(ctx context.Context, principal *oidc.IDToken, pubKey, challenge []byte) (*privatecapb.CertificateConfig_SubjectConfig, error) {
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(principal)
	if !emailVerified {
		return nil, errors.New("email_verified claim was false")
	} else if err != nil {
		return nil, err
	}

	pkixPubKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	// Check the proof
	if err := googleca.CheckSignature(pkixPubKey, challenge, emailAddress); err != nil {
		return nil, err
	}

	// Now issue cert!
	return googleca.EmailSubject(emailAddress), nil
}

func Spiffe(ctx context.Context, principal *oidc.IDToken, pubKey, challenge []byte) (*privatecapb.CertificateConfig_SubjectConfig, error) {

	spiffeID := principal.Subject

	pkixPubKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	cfg := config.Config()

	// The Spiffe ID must be a subdomain of the issuer (spiffe://foo.example.com -> example.com/...)
	u, err := url.Parse(cfg.OIDCIssuers[principal.Issuer].IssuerURL)
	if err != nil {
		return nil, err
	}

	issuerHostname := u.Hostname()
	if !isSpiffeIDAllowed(u.Hostname(), spiffeID) {
		return nil, fmt.Errorf("%s is not allowed for %s", spiffeID, issuerHostname)
	}

	// Check the proof
	if err := googleca.CheckSignature(pkixPubKey, challenge, spiffeID); err != nil {
		return nil, err
	}

	// Now issue cert!
	return googleca.SpiffeSubject(spiffeID), nil
}

func isSpiffeIDAllowed(host, spiffeID string) bool {
	// Strip spiffe://
	name := strings.TrimPrefix(spiffeID, "spiffe://")

	// get the host part
	spiffeDomain := strings.Split(name, "/")[0]

	if spiffeDomain == host {
		return true
	}
	return strings.Contains(spiffeDomain, "."+host)

}
