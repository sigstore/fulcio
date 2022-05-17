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

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ChallengeType int

const (
	EmailValue ChallengeType = iota
	SpiffeValue
	GithubWorkflowValue
	KubernetesValue
	URIValue
	UsernameValue
)

type AdditionalInfo int

// Additional information that can be added as a cert extension.
const (
	GithubWorkflowTrigger AdditionalInfo = iota
	GithubWorkflowSha
	GithubWorkflowName
	GithubWorkflowRepository
	GithubWorkflowRef
)

type ChallengeResult struct {
	Issuer  string
	TypeVal ChallengeType

	// Value configures what will be set for SubjectAlternativeName in
	// the certificate issued.
	Value string

	// Extra information from the token that can be added to extensions.
	AdditionalInfo map[AdditionalInfo]string

	// subject or email from the id token. This must be the thing
	// signed in the proof of possession!
	subject string
}

func (cr *ChallengeResult) Name(context.Context) string {
	return cr.subject
}

func (cr *ChallengeResult) Embed(ctx context.Context, cert *x509.Certificate) error {
	switch cr.TypeVal {
	case EmailValue:
		cert.EmailAddresses = []string{cr.Value}
	case SpiffeValue:
		challengeURL, err := url.Parse(cr.Value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{challengeURL}
	case GithubWorkflowValue:
		jobWorkflowURI, err := url.Parse(cr.Value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{jobWorkflowURI}
	case KubernetesValue:
		k8sURI, err := url.Parse(cr.Value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{k8sURI}
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
	if cr.TypeVal == GithubWorkflowValue {
		var ok bool
		exts.GithubWorkflowTrigger, ok = cr.AdditionalInfo[GithubWorkflowTrigger]
		if !ok {
			return errors.New("github workflow missing trigger claim")
		}
		exts.GithubWorkflowSHA, ok = cr.AdditionalInfo[GithubWorkflowSha]
		if !ok {
			return errors.New("github workflow missing SHA claim")
		}
		exts.GithubWorkflowName, ok = cr.AdditionalInfo[GithubWorkflowName]
		if !ok {
			return errors.New("github workflow missing workflow name claim")
		}
		exts.GithubWorkflowRepository, ok = cr.AdditionalInfo[GithubWorkflowRepository]
		if !ok {
			return errors.New("github workflow missing repository claim")
		}
		exts.GithubWorkflowRef, ok = cr.AdditionalInfo[GithubWorkflowRef]
		if !ok {
			return errors.New("github workflow missing ref claim")
		}
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

func email(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(principal)
	if !emailVerified {
		return nil, errors.New("email_verified claim was false")
	} else if err != nil {
		return nil, err
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: EmailValue,
		Value:   emailAddress,
		subject: emailAddress,
	}, nil
}

func spiffe(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	spiffeID := principal.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	parsed, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse spiffeID: %w", err)
	}

	if parsed.Hostname() != cfg.SPIFFETrustDomain {
		return nil, fmt.Errorf("spiffe id %s doesn't match configured trust domain %s", spiffeID, cfg.SPIFFETrustDomain)
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
		subject: spiffeID,
	}, nil
}

func kubernetes(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	k8sURI, err := kubernetesToken(principal)
	if err != nil {
		return nil, err
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: KubernetesValue,
		Value:   k8sURI,
		subject: principal.Subject,
	}, nil
}

func githubWorkflow(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	workflowRef, err := workflowFromIDToken(principal)
	if err != nil {
		return nil, err
	}
	additionalInfo, err := workflowInfoFromIDToken(principal)
	if err != nil {
		return nil, err
	}

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return &ChallengeResult{
		Issuer:         issuer,
		TypeVal:        GithubWorkflowValue,
		Value:          workflowRef,
		AdditionalInfo: additionalInfo,
		subject:        principal.Subject,
	}, nil
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

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	return &ChallengeResult{
		Issuer:  issuer,
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

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	emailSubject := fmt.Sprintf("%s@%s", username, cfg.SubjectDomain)

	return &ChallengeResult{
		Issuer:  issuer,
		TypeVal: UsernameValue,
		Value:   emailSubject,
		subject: username,
	}, nil
}

func kubernetesToken(token *oidc.IDToken) (string, error) {
	// Extract custom claims
	var claims struct {
		// "kubernetes.io": {
		//   "namespace": "default",
		//   "pod": {
		// 	    "name": "oidc-test",
		// 	    "uid": "49ad3572-b3dd-43a6-8d77-5858d3660275"
		//   },
		//   "serviceaccount": {
		// 	    "name": "default",
		//      "uid": "f5720c1d-e152-4356-a897-11b07aff165d"
		//   }
		// }
		Kubernetes struct {
			Namespace string `json:"namespace"`
			Pod       struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"pod"`
			ServiceAccount struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", err
	}

	// We use this in URIs, so it has to be a URI.
	return "https://kubernetes.io/namespaces/" + claims.Kubernetes.Namespace + "/serviceaccounts/" + claims.Kubernetes.ServiceAccount.Name, nil
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

func workflowInfoFromIDToken(token *oidc.IDToken) (map[AdditionalInfo]string, error) {
	// Extract custom claims
	var claims struct {
		Sha        string `json:"sha"`
		Trigger    string `json:"event_name"`
		Repository string `json:"repository"`
		Workflow   string `json:"workflow"`
		Ref        string `json:"ref"`
		// The other fields that are present here seem to depend on the type
		// of workflow trigger that initiated the action.
	}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	// We use this in URIs, so it has to be a URI.
	return map[AdditionalInfo]string{
		GithubWorkflowSha:        claims.Sha,
		GithubWorkflowTrigger:    claims.Trigger,
		GithubWorkflowName:       claims.Workflow,
		GithubWorkflowRepository: claims.Repository,
		GithubWorkflowRef:        claims.Ref}, nil
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
		principal, err = email(ctx, tok)
	case config.IssuerTypeSpiffe:
		principal, err = spiffe(ctx, tok)
	case config.IssuerTypeGithubWorkflow:
		principal, err = githubWorkflow(ctx, tok)
	case config.IssuerTypeKubernetes:
		principal, err = kubernetes(ctx, tok)
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
