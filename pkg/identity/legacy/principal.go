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

package legacy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spiffe/v2/spiffeid"

	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/oauthflow"
)

type challengeType int

const (
	EmailValue challengeType = iota
	SpiffeValue
	GithubWorkflowValue
	KubernetesValue
	URIValue
	UsernameValue
)

// All hostnames for subject and issuer OIDC claims must have at least a
// top-level and second-level domain
const minimumHostnameLength = 2

type additionalInfo int

// Additional information that can be added as a cert extension.
const (
	githubWorkflowTrigger additionalInfo = iota
	githubWorkflowSha
	githubWorkflowName
	githubWorkflowRepository
	githubWorkflowRef
)

type legacyPrincipal struct {
	issuer  string
	typeVal challengeType

	// Value configures what will be set for SubjectAlternativeName in
	// the certificate issued.
	value string

	// Extra information from the token that can be added to extensions.
	additionalInfo map[additionalInfo]string

	// subject or email from the id token. This must be the thing
	// signed in the proof of possession!
	subject string
}

func (cr *legacyPrincipal) Name(context.Context) string {
	return cr.subject
}

func (cr *legacyPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	switch cr.typeVal {
	case EmailValue:
		cert.EmailAddresses = []string{cr.value}
	case SpiffeValue:
		challengeURL, err := url.Parse(cr.value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{challengeURL}
	case GithubWorkflowValue:
		jobWorkflowURI, err := url.Parse(cr.value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{jobWorkflowURI}
	case KubernetesValue:
		k8sURI, err := url.Parse(cr.value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{k8sURI}
	case URIValue:
		subjectURI, err := url.Parse(cr.value)
		if err != nil {
			return err
		}
		cert.URIs = []*url.URL{subjectURI}
	case UsernameValue:
		cert.EmailAddresses = []string{cr.value}
	}

	exts := x509ca.Extensions{
		Issuer: cr.issuer,
	}
	if cr.typeVal == GithubWorkflowValue {
		var ok bool
		exts.GithubWorkflowTrigger, ok = cr.additionalInfo[githubWorkflowTrigger]
		if !ok {
			return errors.New("github workflow missing trigger claim")
		}
		exts.GithubWorkflowSHA, ok = cr.additionalInfo[githubWorkflowSha]
		if !ok {
			return errors.New("github workflow missing SHA claim")
		}
		exts.GithubWorkflowName, ok = cr.additionalInfo[githubWorkflowName]
		if !ok {
			return errors.New("github workflow missing workflow name claim")
		}
		exts.GithubWorkflowRepository, ok = cr.additionalInfo[githubWorkflowRepository]
		if !ok {
			return errors.New("github workflow missing repository claim")
		}
		exts.GithubWorkflowRef, ok = cr.additionalInfo[githubWorkflowRef]
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

	return &legacyPrincipal{
		issuer:  issuer,
		typeVal: EmailValue,
		value:   emailAddress,
		subject: emailAddress,
	}, nil
}

func spiffe(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	spiffeID := principal.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(cfg.SPIFFETrustDomain)
	if err != nil {
		return nil, fmt.Errorf("unable to parse trust domain from configuration: %s", cfg.SPIFFETrustDomain)
	}

	parsedSpiffeID, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid spiffeid provided: %s", spiffeID)
	}

	if parsedSpiffeID.TrustDomain().Compare(trustDomain) != 0 {
		return nil, fmt.Errorf("spiffe ID trust domain %s doesn't match configured trust domain %s", parsedSpiffeID.TrustDomain(), trustDomain)
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &legacyPrincipal{
		issuer:  issuer,
		typeVal: SpiffeValue,
		value:   spiffeID,
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

	return &legacyPrincipal{
		issuer:  issuer,
		typeVal: KubernetesValue,
		value:   k8sURI,
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

	return &legacyPrincipal{
		issuer:         issuer,
		typeVal:        GithubWorkflowValue,
		value:          workflowRef,
		additionalInfo: additionalInfo,
		subject:        principal.Subject,
	}, nil
}

func uri(ctx context.Context, principal *oidc.IDToken) (identity.Principal, error) {
	uriWithSubject := principal.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
	if !ok {
		return nil, errors.New("invalid configuration for OIDC ID Token issuer")
	}

	uSubject, err := url.Parse(uriWithSubject)
	if err != nil {
		return nil, err
	}

	// The subject prefix URI must match the domain (excluding the subdomain) of the issuer
	// In order to declare this configuration, a test must have been done to prove ownership
	// over both the issuer and domain configuration values.
	// Valid examples:
	// * uriWithSubject = https://example.com/users/user1, issuer = https://accounts.example.com
	// * uriWithSubject = https://accounts.example.com/users/user1, issuer = https://accounts.example.com
	// * uriWithSubject = https://users.example.com/users/user1, issuer = https://accounts.example.com
	uIssuer, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	// Check that:
	// * The URI schemes match
	// * Either the hostnames exactly match or the top level and second level domains match
	if err := isURISubjectAllowed(uSubject, uIssuer); err != nil {
		return nil, err
	}

	// The subject hostname must exactly match the subject domain from the configuration
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

	return &legacyPrincipal{
		issuer:  issuer,
		typeVal: URIValue,
		value:   uriWithSubject,
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

	// The domain in the configuration must match the domain (excluding the subdomain) of the issuer
	// In order to declare this configuration, a test must have been done to prove ownership
	// over both the issuer and domain configuration values.
	// Valid examples:
	// * domain = https://example.com/users/user1, issuer = https://accounts.example.com
	// * domain = https://accounts.example.com/users/user1, issuer = https://accounts.example.com
	// * domain = https://users.example.com/users/user1, issuer = https://accounts.example.com
	uIssuer, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	if err := validateAllowedDomain(cfg.SubjectDomain, uIssuer.Hostname()); err != nil {
		return nil, err
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	emailSubject := fmt.Sprintf("%s@%s", username, cfg.SubjectDomain)

	return &legacyPrincipal{
		issuer:  issuer,
		typeVal: UsernameValue,
		value:   emailSubject,
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

func workflowInfoFromIDToken(token *oidc.IDToken) (map[additionalInfo]string, error) {
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
	return map[additionalInfo]string{
		githubWorkflowSha:        claims.Sha,
		githubWorkflowTrigger:    claims.Trigger,
		githubWorkflowName:       claims.Workflow,
		githubWorkflowRepository: claims.Repository,
		githubWorkflowRef:        claims.Ref}, nil
}

// isURISubjectAllowed compares the subject and issuer URIs,
// returning an error if the scheme or the hostnames do not match
func isURISubjectAllowed(subject, issuer *url.URL) error {
	if subject.Scheme != issuer.Scheme {
		return fmt.Errorf("subject (%s) and issuer (%s) URI schemes do not match", subject.Scheme, issuer.Scheme)
	}

	return validateAllowedDomain(subject.Hostname(), issuer.Hostname())
}

// validateAllowedDomain compares two hostnames, returning an error if the
// top-level and second-level domains do not match
func validateAllowedDomain(subjectHostname, issuerHostname string) error {
	// If the hostnames exactly match, return early
	if subjectHostname == issuerHostname {
		return nil
	}

	// Compare the top level and second level domains
	sHostname := strings.Split(subjectHostname, ".")
	iHostname := strings.Split(issuerHostname, ".")
	if len(sHostname) < minimumHostnameLength {
		return fmt.Errorf("URI hostname too short: %s", subjectHostname)
	}
	if len(iHostname) < minimumHostnameLength {
		return fmt.Errorf("URI hostname too short: %s", issuerHostname)
	}
	if sHostname[len(sHostname)-1] == iHostname[len(iHostname)-1] &&
		sHostname[len(sHostname)-2] == iHostname[len(iHostname)-2] {
		return nil
	}
	return fmt.Errorf("hostname top-level and second-level domains do not match: %s, %s", subjectHostname, issuerHostname)
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
