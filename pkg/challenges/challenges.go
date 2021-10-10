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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/oauthflow"
)

type ChallengeType int

const (
	EmailValue ChallengeType = iota
	SpiffeValue
	GithubWorkflowValue
)

type ChallengeResult struct {
	Issuer  string
	TypeVal ChallengeType
	Value   string
}

func CheckSignature(pub crypto.PublicKey, proof []byte, email string) error {
	h := sha256.Sum256([]byte(email))

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ok := ecdsa.VerifyASN1(k, h[:], proof); !ok {
			return errors.New("signature could not be verified")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], proof); err != nil {
			return fmt.Errorf("signature could not be verified: %v", err)
		}
	}

	return nil
}

func Email(ctx context.Context, principal *oidc.IDToken, pubKey, challenge []byte) (*ChallengeResult, error) {
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
	if err := CheckSignature(pkixPubKey, challenge, emailAddress); err != nil {
		return nil, err
	}

	globalCfg := config.Config()
	cfg, ok := globalCfg.OIDCIssuers[principal.Issuer]
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: EmailValue,
		Value:   emailAddress,
	}, nil
}

func Spiffe(ctx context.Context, principal *oidc.IDToken, pubKey, challenge []byte) (*ChallengeResult, error) {

	spiffeID := principal.Subject

	pkixPubKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	globalCfg := config.Config()
	cfg, ok := globalCfg.OIDCIssuers[principal.Issuer]
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	// The Spiffe ID must be a subdomain of the issuer (spiffe://foo.example.com -> example.com/...)
	u, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	issuerHostname := u.Hostname()
	if !isSpiffeIDAllowed(u.Hostname(), spiffeID) {
		return nil, fmt.Errorf("%s is not allowed for %s", spiffeID, issuerHostname)
	}

	// Check the proof
	if err := CheckSignature(pkixPubKey, challenge, spiffeID); err != nil {
		return nil, err
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: SpiffeValue,
		Value:   spiffeID,
	}, nil
}

func GithubWorkflow(ctx context.Context, principal *oidc.IDToken, pubKey, challenge []byte) (*ChallengeResult, error) {
	workflowRef, err := workflowFromIDToken(principal)
	if err != nil {
		return nil, err
	}

	pkixPubKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	// Check the proof
	if err := CheckSignature(pkixPubKey, challenge, principal.Subject); err != nil {
		return nil, err
	}

	globalCfg := config.Config()
	cfg, ok := globalCfg.OIDCIssuers[principal.Issuer]
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: GithubWorkflowValue,
		Value:   workflowRef,
	}, nil
}

func workflowFromIDToken(token *oidc.IDToken) (string, error) {
	// Extract custom claims
	var claims struct {
		JobWorkflowRef string `json:"job_workflow_ref"`
		// The other fields that are present here seem to depend on the type
		// of workflow trigger that initiated the action.
	}
	if err := token.Claims(&claims); err != nil {
		return "", err
	}

	// We use this in URIs, so it has to be a URI.
	return "https://github.com/" + claims.JobWorkflowRef, nil
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
