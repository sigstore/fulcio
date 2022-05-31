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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/identity/email"
	"github.com/sigstore/fulcio/pkg/identity/github"
	"github.com/sigstore/fulcio/pkg/identity/kubernetes"
	"github.com/sigstore/fulcio/pkg/identity/spiffe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ChallengeType int

const (
	URIValue ChallengeType = iota
	UsernameValue
)

type ChallengeResult struct {
	Issuer  string
	TypeVal ChallengeType

	// Value configures what will be set for SubjectAlternativeName in
	// the certificate issued.
	Value string

	// subject or email from the id token. This must be the thing
	// signed in the proof of possession!
	subject string
}

func (cr *ChallengeResult) Name(context.Context) string {
	return cr.subject
}

func (cr *ChallengeResult) Embed(ctx context.Context, cert *x509.Certificate) error {
	switch cr.TypeVal {
	case URIValue:
		subjectURI, err := url.Parse(cr.Value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{subjectURI}
	case UsernameValue:
		cert.EmailAddresses = []string{cr.Value}
	}

	exts := x509ca.Extensions{
		Issuer: cr.Issuer,
	}

	var err error
	cert.ExtraExtensions, err = exts.Render()
	if err != nil {
		return err
	}

	return nil
}

// CheckSignature verifies a challenge, a signature over the subject or email
// of an OIDC token
func CheckSignature(pub crypto.PublicKey, proof []byte, subject string) error {
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	return verifier.VerifySignature(bytes.NewReader(proof), strings.NewReader(subject))
}

func uri(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	uriWithSubject := principal.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
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

	return &ChallengeResult{
		Issuer:  principal.Issuer,
		TypeVal: URIValue,
		Value:   uriWithSubject,
		subject: uriWithSubject,
	}, nil
}

func username(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	username := principal.Subject

	if strings.Contains(username, "@") {
		return nil, errors.New("username cannot contain @ character")
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	emailSubject := fmt.Sprintf("%s@%s", username, cfg.SubjectDomain)

	return &ChallengeResult{
		Issuer:  principal.Issuer,
		TypeVal: UsernameValue,
		Value:   emailSubject,
		subject: username,
	}, nil
}

func PrincipalFromIDToken(ctx context.Context, tok *oidc.IDToken) (identity.Principal, error) {
	iss, ok := config.FromContext(ctx).GetIssuer(tok.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", tok.Issuer)
	}
	var principal identity.Principal
	var err error
	switch iss.Type {
	case config.IssuerTypeEmail:
		principal, err = email.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeSpiffe:
		principal, err = spiffe.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeGithubWorkflow:
		principal, err = github.WorkflowPrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeKubernetes:
		principal, err = kubernetes.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeURI:
		principal, err = uri(ctx, tok)
	case config.IssuerTypeUsername:
		principal, err = username(ctx, tok)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)
	}
	if err != nil {
		return nil, err
	}

	return principal, nil
}

// ParsePublicKey parses a PEM or DER encoded public key. Returns an error if
// decoding fails or if no public key is found.
func ParsePublicKey(encodedPubKey string) (crypto.PublicKey, error) {
	if len(encodedPubKey) == 0 {
		return nil, errors.New("public key not provided")
	}
	// try to unmarshal as PEM
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(encodedPubKey))
	if err != nil {
		// try to unmarshal as DER
		publicKey, err = x509.ParsePKIXPublicKey([]byte(encodedPubKey))
		if err != nil {
			return nil, errors.New("error parsing PEM or DER encoded public key")
		}
	}
	return publicKey, err
}
