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
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/oauthflow"
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

// All hostnames for subject and issuer OIDC claims must have at least a
// top-level and second-level domain
const minimumHostnameLength = 2

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
	Issuer    string
	TypeVal   ChallengeType
	PublicKey crypto.PublicKey
	Value     string
	// Extra information from the token that can be added to extensions.
	AdditionalInfo map[AdditionalInfo]string
}

func CheckSignature(pub crypto.PublicKey, proof []byte, email string) error {
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	return verifier.VerifySignature(bytes.NewReader(proof), strings.NewReader(email))
}

func Email(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(principal)
	if !emailVerified {
		return nil, errors.New("email_verified claim was false")
	} else if err != nil {
		return nil, err
	}

	// Check the proof
	if err := CheckSignature(pubKey, challenge, emailAddress); err != nil {
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

	// Now issue cert!
	return &ChallengeResult{
		Issuer:    issuer,
		PublicKey: pubKey,
		TypeVal:   EmailValue,
		Value:     emailAddress,
	}, nil
}

func Spiffe(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {

	spiffeID := principal.Subject

	cfg, ok := config.FromContext(ctx).GetIssuer(principal.Issuer)
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
	if err := CheckSignature(pubKey, challenge, spiffeID); err != nil {
		return nil, err
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &ChallengeResult{
		Issuer:    issuer,
		PublicKey: pubKey,
		TypeVal:   SpiffeValue,
		Value:     spiffeID,
	}, nil
}

func Kubernetes(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {
	k8sURI, err := kubernetesToken(principal)
	if err != nil {
		return nil, err
	}

	// Check the proof
	if err := CheckSignature(pubKey, challenge, principal.Subject); err != nil {
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

	// Now issue cert!
	return &ChallengeResult{
		Issuer:    issuer,
		PublicKey: pubKey,
		TypeVal:   KubernetesValue,
		Value:     k8sURI,
	}, nil
}

func GithubWorkflow(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {
	workflowRef, err := workflowFromIDToken(principal)
	if err != nil {
		return nil, err
	}
	additionalInfo, err := workflowInfoFromIDToken(principal)
	if err != nil {
		return nil, err
	}

	// Check the proof
	if err := CheckSignature(pubKey, challenge, principal.Subject); err != nil {
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

	// Now issue cert!
	return &ChallengeResult{
		Issuer:         issuer,
		PublicKey:      pubKey,
		TypeVal:        GithubWorkflowValue,
		Value:          workflowRef,
		AdditionalInfo: additionalInfo,
	}, nil
}

func URI(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {
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

	// Check the proof - A signature over the OIDC token subject
	if err := CheckSignature(pubKey, challenge, uriWithSubject); err != nil {
		return nil, err
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	// Now issue cert!
	return &ChallengeResult{
		Issuer:    issuer,
		PublicKey: pubKey,
		TypeVal:   URIValue,
		Value:     uriWithSubject,
	}, nil
}

func Username(ctx context.Context, principal *oidc.IDToken, pubKey crypto.PublicKey, challenge []byte) (*ChallengeResult, error) {
	username := principal.Subject

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
	if err := isDomainAllowed(cfg.SubjectDomain, uIssuer.Hostname()); err != nil {
		return nil, err
	}

	// Check the proof - A signature over the OIDC token subject
	if err := CheckSignature(pubKey, challenge, username); err != nil {
		return nil, err
	}

	issuer, err := oauthflow.IssuerFromIDToken(principal, cfg.IssuerClaim)
	if err != nil {
		return nil, err
	}

	emailSubject := fmt.Sprintf("%s@%s", username, cfg.SubjectDomain)

	// Now issue cert!
	return &ChallengeResult{
		Issuer:    issuer,
		PublicKey: pubKey,
		TypeVal:   UsernameValue,
		Value:     emailSubject,
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

func isSpiffeIDAllowed(host, spiffeID string) bool {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return false
	}
	if u.Scheme != "spiffe" {
		return false
	}
	if u.Hostname() == host {
		return true
	}
	return strings.Contains(u.Hostname(), "."+host)
}

// isURISubjectAllowed compares the subject and issuer URIs,
// returning an error if the scheme or the hostnames do not match
func isURISubjectAllowed(subject, issuer *url.URL) error {
	if subject.Scheme != issuer.Scheme {
		return fmt.Errorf("subject (%s) and issuer (%s) URI schemes do not match", subject.Scheme, issuer.Scheme)
	}

	return isDomainAllowed(subject.Hostname(), issuer.Hostname())
}

// isDomainAllowed compares two hostnames, returning an error if the
// top-level and second-level domains do not match
func isDomainAllowed(subjectHostname, issuerHostname string) error {
	// If the hostnames exactly match, return early
	if subjectHostname == issuerHostname {
		return nil
	}

	// Compare the top level and second level domains
	sHostname := strings.Split(subjectHostname, ".")
	iHostname := strings.Split(issuerHostname, ".")
	if len(sHostname) < minimumHostnameLength {
		return fmt.Errorf("subject URI hostname too short: %s", subjectHostname)
	}
	if len(iHostname) < minimumHostnameLength {
		return fmt.Errorf("issuer URI hostname too short: %s", issuerHostname)
	}
	if sHostname[len(sHostname)-1] == iHostname[len(iHostname)-1] &&
		sHostname[len(sHostname)-2] == iHostname[len(iHostname)-2] {
		return nil
	}
	return fmt.Errorf("subject and issuer hostnames do not match: %s, %s", subjectHostname, issuerHostname)
}
