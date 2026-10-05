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

package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sigstore/fulcio/pkg/certificate"
	fulciogrpc "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.yaml.in/yaml/v3"
)

const defaultOIDCDiscoveryTimeout = 10 * time.Second

// All hostnames for subject and issuer OIDC claims must have at least a
// top-level and second-level domain
const minimumHostnameLength = 2

type verifierWithConfig struct {
	*oidc.IDTokenVerifier
	*oidc.Config
}

type bearerTokenTransport struct {
	Transport http.RoundTripper
	Token     string
	IssuerURL string
}

func (t *bearerTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	parsedIssuer, err := url.Parse(t.IssuerURL)
	if err != nil {
		return nil, err
	}
	if req.URL.Host == parsedIssuer.Host {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	} else {
		return nil, fmt.Errorf("issuer URL host %s does not match request URL host %s", parsedIssuer.Host, req.URL.Host)
	}
	return t.Transport.RoundTrip(req)
}

type FulcioConfig struct {
	OIDCIssuers map[string]OIDCIssuer `json:"OIDCIssuers,omitempty" yaml:"oidc-issuers,omitempty"`

	// A meta issuer has a templated URL of the form:
	//   https://oidc.eks.*.amazonaws.com/id/*
	// Where * can match a single hostname or URI path parts
	// (in particular, no '.' or '/' are permitted, among
	// other special characters)  Some examples we want to match:
	// * https://oidc.eks.us-west-2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB
	// * https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us-west1-b/clusters/tenant-cluster
	MetaIssuers map[string]OIDCIssuer `json:"MetaIssuers,omitempty" yaml:"meta-issuers,omitempty"`

	// It defines metadata to be used for the CIProvider identity provider principal.
	// The CI provider has a generic logic for ci providers, this metadata is used
	// to define the right behavior for each ci provider that is defined
	// on the configuration file
	CIIssuerMetadata map[string]IssuerMetadata `json:"CIIssuerMetadata,omitempty" yaml:"ci-issuer-metadata,omitempty"`

	// verifiers is a fixed mapping from our OIDCIssuers to their OIDC verifiers.
	verifiers map[string][]*verifierWithConfig
	// lru is an LRU cache of recently used verifiers for our meta issuers.
	lru *lru.TwoQueueCache[string, []*verifierWithConfig]
	// blockedCIDRs is a list of additional IP ranges to block in the OIDC HTTP client dialer.
	blockedCIDRs []*net.IPNet
}

type IssuerMetadata struct {
	// Defaults contains key-value pairs that can be used for filling the templates from ExtensionTemplates
	// If a key cannot be found on the token claims, the template will use the defaults
	DefaultTemplateValues map[string]string `json:"DefaultTemplateValues,omitempty" yaml:"default-template-values,omitempty"`
	// ExtensionTemplates contains a mapping between certificate extension and token claim
	// Provide either strings following https://pkg.go.dev/text/template syntax,
	// e.g "{{ .url }}/{{ .repository }}"
	// or non-templated strings with token claim keys to be replaced,
	// e.g "job_workflow_sha"
	ExtensionTemplates certificate.Extensions `json:"ExtensionTemplates" yaml:"extension-templates,omitempty"`
	// Template for the Subject Alternative Name extension
	// It's typically the same value as Build Signer URI
	SubjectAlternativeNameTemplate string `json:"SubjectAlternativeNameTemplate,omitempty" yaml:"subject-alternative-name-template,omitempty"`
}

type OIDCIssuer struct {
	// The expected issuer of an OIDC token
	IssuerURL string `json:"IssuerURL,omitempty" yaml:"issuer-url,omitempty"`
	// The expected client ID of the OIDC token
	ClientID string `json:"ClientID" yaml:"client-id,omitempty"`
	// Used to determine the subject of the certificate and if additional
	// certificate values are needed
	Type IssuerType `json:"Type" yaml:"type,omitempty"`
	// CIProvider is an optional configuration to map token claims to extensions for CI workflows
	CIProvider string `json:"CIProvider,omitempty" yaml:"ci-provider,omitempty"`
	// Optional, if the issuer is in a different claim in the OIDC token
	IssuerClaim string `json:"IssuerClaim,omitempty" yaml:"issuer-claim,omitempty"`
	// The domain that must be present in the subject for 'uri' issuer types
	// Also used to create an email for 'username' issuer types
	SubjectDomain string `json:"SubjectDomain,omitempty" yaml:"subject-domain,omitempty"`
	// SPIFFETrustDomain specifies the trust domain that 'spiffe' issuer types
	// issue ID tokens for. Tokens with a different trust domain will be
	// rejected.
	SPIFFETrustDomain string `json:"SPIFFETrustDomain,omitempty" yaml:"spiffe-trust-domain,omitempty"`
	// Optional, the challenge claim expected for the issuer
	// Set if using a custom issuer
	ChallengeClaim string `json:"ChallengeClaim,omitempty" yaml:"challenge-claim,omitempty"`
	// Optional, the description for the issuer
	Description string `json:"Description,omitempty" yaml:"description,omitempty"`
	// Optional, the contact for the issuer team
	// Usually it is a email
	Contact string `json:"Contact,omitempty" yaml:"contact,omitempty"`
	// Environment specifies whether this issuer is restricted to a specific environment
	// (e.g. "staging" or "production"). If omitted, it is valid in all environments.
	Environment string `json:"Environment,omitempty" yaml:"environment,omitempty"`

	// CACert is an optional parameter that holds the CA certificate in PEM format.
	// This is used to trust the TLS certificate signed by an internal CA when interacting
	// with some OIDC providers, preventing x509 certificate verification failures.
	CACert string `json:"CACert,omitempty" yaml:"ca-cert,omitempty"`

	// SkipEmailVerification skips the email_verified claim check for email-type issuers.
	// This should only be set to true for trusted internal identity providers (e.g., Microsoft Entra, ADFS)
	// that perform email verification through their own processes but don't include the email_verified claim.
	SkipEmailVerification bool `json:"SkipEmailVerification,omitempty" yaml:"skip-email-verification,omitempty"`
}

func MetaRegex(issuer string) (*regexp.Regexp, error) {
	// Quote all of the "meta" characters like `.` to avoid
	// those literal characters in the URL matching any character.
	// This will ALSO quote `*`, so we replace the quoted version.
	quoted := regexp.QuoteMeta(issuer)

	// Replace the quoted `*` with a regular expression that
	// will match alpha-numeric parts with common additional
	// "special" characters.
	replaced := strings.ReplaceAll(quoted, regexp.QuoteMeta("*"), "[-_a-zA-Z0-9]+")

	// Add anchors to the beginning and end of the regular expression
	// to prevent matching URLs where the issuer is not the host of the URL,
	// e.g. http://localhost:3000?https://meta-url-issuer.com/*
	// Resolves GHSA-59jp-pj84-45mr
	replaced = "^" + replaced + "$"

	// Compile into a regular expression.
	return regexp.Compile(replaced)
}

// GetIssuer looks up the issuer configuration for an `issuerURL`
// coming from an incoming OIDC token.  If no matching configuration
// is found, then it returns `false`.
func (fc *FulcioConfig) GetIssuer(issuerURL string) (OIDCIssuer, bool) {
	iss, ok := fc.OIDCIssuers[issuerURL]
	if ok {
		return iss, ok
	}

	for meta, iss := range fc.MetaIssuers {
		re, err := MetaRegex(meta)
		if err != nil {
			continue // Shouldn't happen, we check parsing the config
		}
		if re.MatchString(issuerURL) {
			// If it matches, then return a concrete OIDCIssuer
			// configuration for this issuer URL.
			return OIDCIssuer{
				IssuerURL:             issuerURL,
				ClientID:              iss.ClientID,
				Type:                  iss.Type,
				IssuerClaim:           iss.IssuerClaim,
				SubjectDomain:         iss.SubjectDomain,
				CIProvider:            iss.CIProvider,
				SkipEmailVerification: iss.SkipEmailVerification,
				CACert:                iss.CACert,
			}, true
		}
	}

	return OIDCIssuer{}, false
}

// GetVerifier fetches a token verifier for the given `issuerURL`
// coming from an incoming OIDC token.  If no matching configuration
// is found, then it returns `false`.
func (fc *FulcioConfig) GetVerifier(issuerURL string, opts ...InsecureOIDCConfigOption) (*oidc.IDTokenVerifier, bool) {
	iss, ok := fc.GetIssuer(issuerURL)
	if !ok {
		return nil, false
	}
	cfg := &oidc.Config{ClientID: iss.ClientID}
	for _, o := range opts {
		o(cfg)
	}
	// Look up our fixed issuer verifiers
	v, ok := fc.verifiers[issuerURL]
	if ok {
		for _, c := range v {
			if reflect.DeepEqual(c.Config, cfg) {
				return c.IDTokenVerifier, true
			}
		}
	}

	// Look in the LRU cache for a verifier
	v, ok = fc.lru.Get(issuerURL)
	if ok {
		for _, c := range v {
			if reflect.DeepEqual(c.Config, cfg) {
				return c.IDTokenVerifier, true
			}
		}
	}

	// If this issuer hasn't been recently used, or we have special config options, then create a new verifier
	// and add it to the LRU cache.

	client, err := httpClientForIssuer(fc, iss)
	if err != nil {
		log.Logger.Warnf("error building http client for issuer %q: %s", iss.IssuerURL, err)
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCDiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuerURL)
	if err != nil {
		log.Logger.Errorf("Failed to create provider for issuer URL %q: %v", issuerURL, err)
		return nil, false
	}

	vwf := &verifierWithConfig{provider.Verifier(cfg), cfg}
	if v == nil {
		v = []*verifierWithConfig{vwf}
	} else {
		v = append(v, vwf)
	}

	fc.lru.Add(issuerURL, v)
	return vwf.IDTokenVerifier, true
}

type InsecureOIDCConfigOption func(opt *oidc.Config)

func WithSkipExpiryCheck() InsecureOIDCConfigOption {
	return func(c *oidc.Config) {
		c.SkipExpiryCheck = true
	}
}

// ToIssuers returns a proto representation of the OIDC issuer configuration.
func (fc *FulcioConfig) ToIssuers() []*fulciogrpc.OIDCIssuer {
	var issuers []*fulciogrpc.OIDCIssuer

	for _, cfgIss := range fc.OIDCIssuers {
		issuer := &fulciogrpc.OIDCIssuer{
			Issuer:                &fulciogrpc.OIDCIssuer_IssuerUrl{IssuerUrl: cfgIss.IssuerURL},
			Audience:              cfgIss.ClientID,
			SpiffeTrustDomain:     cfgIss.SPIFFETrustDomain,
			ChallengeClaim:        issuerToChallengeClaim(cfgIss.Type, cfgIss.ChallengeClaim),
			IssuerType:            cfgIss.Type.String(),
			SubjectDomain:         cfgIss.SubjectDomain,
			SkipEmailVerification: cfgIss.SkipEmailVerification,
		}
		issuers = append(issuers, issuer)
	}

	for metaIss, cfgIss := range fc.MetaIssuers {
		issuer := &fulciogrpc.OIDCIssuer{
			Issuer:                &fulciogrpc.OIDCIssuer_WildcardIssuerUrl{WildcardIssuerUrl: metaIss},
			Audience:              cfgIss.ClientID,
			SpiffeTrustDomain:     cfgIss.SPIFFETrustDomain,
			ChallengeClaim:        issuerToChallengeClaim(cfgIss.Type, cfgIss.ChallengeClaim),
			IssuerType:            cfgIss.Type.String(),
			SubjectDomain:         cfgIss.SubjectDomain,
			SkipEmailVerification: cfgIss.SkipEmailVerification,
		}
		issuers = append(issuers, issuer)
	}

	return issuers
}

func noRedirectClient(client *http.Client) *http.Client {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("oidc: redirect to different host %q blocked", req.URL.Host)
		}
		return nil
	}
	return client
}

func httpClientForIssuer(fc *FulcioConfig, iss OIDCIssuer) (*http.Client, error) {
	transportProvider := func(transport *http.Transport) http.RoundTripper {
		return transport
	}

	_, hasK8SIssuer := fc.GetIssuer(k8sIssuerURL)
	_, isConfiguredOIDCIssuer := fc.OIDCIssuers[iss.IssuerURL]
	isTrustedK8sIssuer := iss.Type == IssuerTypeKubernetes && hasK8SIssuer && (isConfiguredOIDCIssuer || iss.IssuerURL == k8sIssuerURL)
	if isTrustedK8sIssuer {
		// Add the Kubernetes cluster's CA to the client's CA pool
		certs, err := os.ReadFile(k8sCA)
		if err != nil {
			return nil, fmt.Errorf("unable to read cluster CA file: %w", err)
		}
		iss.CACert = string(certs)

		if _, err := os.Stat(k8sTokenFile); err == nil {
			// add the authentication header
			tokenBytes, err := os.ReadFile(k8sTokenFile)
			if err != nil {
				return nil, fmt.Errorf("unable to read cluster token file: %w", err)
			}
			transportProvider = func(transport *http.Transport) http.RoundTripper {
				return &bearerTokenTransport{
					Transport: transport,
					Token:     string(tokenBytes),
					IssuerURL: iss.IssuerURL,
				}
			}
		} else {
			if errors.Is(err, os.ErrNotExist) {
				log.Logger.Warnf("Kubernetes token file can't be found on path: %s", k8sTokenFile)
			} else {
				return nil, err
			}
		}
	}

	allowPrivate := isConfiguredOIDCIssuer || isTrustedK8sIssuer
	d, err := getSafeDialer(iss.IssuerURL, allowPrivate, fc.blockedCIDRs)
	if err != nil {
		return nil, err
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("failed to initialize default http transport")
	}
	transport = transport.Clone()
	transport.DialContext = d.DialContext

	if iss.CACert != "" {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		if ok := rootCAs.AppendCertsFromPEM([]byte(iss.CACert)); !ok {
			return nil, fmt.Errorf("failed to append custom CA cert for issuer URL %q", iss.IssuerURL)
		}

		transport.TLSClientConfig = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}

	return noRedirectClient(&http.Client{Transport: transportProvider(transport)}), nil
}

func (fc *FulcioConfig) prepare() error {
	fc.verifiers = make(map[string][]*verifierWithConfig, len(fc.OIDCIssuers))
	for _, iss := range fc.OIDCIssuers {
		if err := fc.insertVerifier(iss); err != nil {
			log.Logger.Errorf("error creating provider for issuer URL %q: %v", iss.IssuerURL, err)
			continue
		}
	}

	cache, err := lru.New2Q[string, []*verifierWithConfig](100 /* size */)
	if err != nil {
		return fmt.Errorf("lru: %w", err)
	}
	fc.lru = cache
	return nil
}

var (
	k8sCA = "/var/run/fulcio/ca.crt"
	// k8sTokenFile specifies the standard path where Kubernetes automatically
	// mounts the projected service account token for a pod.
	// This path is publicly known and not a sensitive credential itself,
	// hence the Gosec G101 warning is a false positive and is suppressed.
	// #nosec G101
	k8sTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sIssuerURL = "https://kubernetes.default.svc"
)

func (fc *FulcioConfig) insertVerifier(iss OIDCIssuer) error {
	client, err := httpClientForIssuer(fc, iss)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCDiscoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), iss.IssuerURL)
	if err != nil {
		return err
	}
	cfg := &oidc.Config{ClientID: iss.ClientID}
	fc.verifiers[iss.IssuerURL] = []*verifierWithConfig{{provider.Verifier(cfg), cfg}}
	return nil
}

type IssuerType string

func (it IssuerType) String() string {
	return string(it)
}

const (
	IssuerTypeBuildkiteJob      = "buildkite-job"
	IssuerTypeEmail             = "email"
	IssuerTypeGithubWorkflow    = "github-workflow"
	IssuerTypeCodefreshWorkflow = "codefresh-workflow"
	IssuerTypeGitLabPipeline    = "gitlab-pipeline"
	IssuerTypeChainguard        = "chainguard-identity"
	IssuerTypeKubernetes        = "kubernetes"
	IssuerTypeSpiffe            = "spiffe"
	IssuerTypeURI               = "uri"
	IssuerTypeUsername          = "username"
	IssuerTypeCIProvider        = "ci-provider"
)

func parseConfig(b []byte) (cfg *FulcioConfig, err error) {
	cfg = &FulcioConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		if err = yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}
	}

	return cfg, nil
}

func validateConfig(conf *FulcioConfig) error {
	if conf == nil {
		return errors.New("nil config")
	}

	for _, issuer := range conf.OIDCIssuers {
		if issuer.CACert != "" {
			rootCAs := x509.NewCertPool()
			if ok := rootCAs.AppendCertsFromPEM([]byte(issuer.CACert)); !ok {
				return fmt.Errorf("failed to parse CA certificate for issuer %s", issuer.IssuerURL)
			}
		}

		if issuer.IssuerClaim != "" && issuer.Type != IssuerTypeEmail {
			return errors.New("only email issuers can use issuer claim mapping")
		}
		if issuer.Type == IssuerTypeSpiffe {
			if issuer.SPIFFETrustDomain == "" {
				return errors.New("spiffe issuer must have SPIFFETrustDomain set")
			}
			// verify that trust domain is valid
			if _, err := spiffeid.TrustDomainFromString(issuer.SPIFFETrustDomain); err != nil {
				return errors.New("spiffe trust domain is invalid")
			}
		}
		if issuer.Type == IssuerTypeURI {
			if issuer.SubjectDomain == "" {
				return errors.New("uri issuer must have SubjectDomain set")
			}
			uDomain, err := url.Parse(issuer.SubjectDomain)
			if err != nil {
				return err
			}
			if uDomain.Scheme == "" {
				return errors.New("SubjectDomain for uri must contain scheme")
			}
			uIssuer, err := url.Parse(issuer.IssuerURL)
			if err != nil {
				return err
			}
			if uIssuer.Scheme == "" {
				return errors.New("issuer for uri must contain scheme")
			}
			// The domain in the configuration must match the domain (excluding the subdomain) of the issuer
			// In order to declare this configuration, a test must have been done to prove ownership
			// over both the issuer and domain configuration values.
			// Valid examples:
			// * SubjectDomain = https://example.com, IssuerURL = https://accounts.example.com
			// * SubjectDomain = https://accounts.example.com, IssuerURL = https://accounts.example.com
			// * SubjectDomain = https://users.example.com, IssuerURL = https://accounts.example.com
			if err := isURISubjectAllowed(uDomain, uIssuer); err != nil {
				return err
			}
		}
		if issuer.Type == IssuerTypeUsername {
			if issuer.SubjectDomain == "" {
				return errors.New("username issuer must have SubjectDomain set")
			}
			uDomain, err := url.Parse(issuer.SubjectDomain)
			if err != nil {
				return err
			}
			if uDomain.Scheme != "" {
				return errors.New("SubjectDomain for username should not contain scheme")
			}
			uIssuer, err := url.Parse(issuer.IssuerURL)
			if err != nil {
				return err
			}
			if uIssuer.Scheme == "" {
				return errors.New("issuer for username must contain scheme")
			}
			// The domain in the configuration must match the domain (excluding the subdomain) of the issuer
			// In order to declare this configuration, a test must have been done to prove ownership
			// over both the issuer and domain configuration values.
			// Valid examples:
			// * SubjectDomain = example.com, IssuerURL = https://accounts.example.com
			// * SubjectDomain = accounts.example.com, IssuerURL = https://accounts.example.com
			// * SubjectDomain = users.example.com, IssuerURL = https://accounts.example.com
			if err := validateAllowedDomain(issuer.SubjectDomain, uIssuer.Hostname()); err != nil {
				return err
			}
		}

		if issuerToChallengeClaim(issuer.Type, issuer.ChallengeClaim) == "" {
			return errors.New("issuer missing challenge claim")
		}
	}

	for _, metaIssuer := range conf.MetaIssuers {
		if metaIssuer.CACert != "" {
			rootCAs := x509.NewCertPool()
			if ok := rootCAs.AppendCertsFromPEM([]byte(metaIssuer.CACert)); !ok {
				return fmt.Errorf("failed to parse CA certificate for meta issuer %s", metaIssuer.IssuerURL)
			}
		}

		if metaIssuer.Type == IssuerTypeSpiffe {
			// This would establish a many to one relationship for OIDC issuers
			// to trust domains so we fail early and reject this configuration.
			return errors.New("SPIFFE meta issuers not supported")
		}

		if issuerToChallengeClaim(metaIssuer.Type, metaIssuer.ChallengeClaim) == "" {
			return errors.New("issuer missing challenge claim")
		}
	}

	return validateCIIssuerMetadata(conf)
}

var DefaultConfig = &FulcioConfig{
	OIDCIssuers: map[string]OIDCIssuer{
		"https://oauth2.sigstore.dev/auth": {
			IssuerURL:   "https://oauth2.sigstore.dev/auth",
			ClientID:    "sigstore",
			IssuerClaim: "$.federated_claims.connector_id",
			Type:        IssuerTypeEmail,
		},
		"https://accounts.google.com": {
			IssuerURL: "https://accounts.google.com",
			ClientID:  "sigstore",
			Type:      IssuerTypeEmail,
		},
		"https://token.actions.githubusercontent.com": {
			IssuerURL: "https://token.actions.githubusercontent.com",
			ClientID:  "sigstore",
			Type:      IssuerTypeGithubWorkflow,
		},
	},
}

type configKey struct{}

func With(ctx context.Context, cfg *FulcioConfig) context.Context {
	ctx = context.WithValue(ctx, configKey{}, cfg)
	return ctx
}

func FromContext(ctx context.Context) *FulcioConfig {
	untyped := ctx.Value(configKey{})
	if untyped == nil {
		return nil
	}
	return untyped.(*FulcioConfig)
}

// It checks that the templates defined are parseable
// We should check it during the service bootstrap to avoid errors further
func validateCIIssuerMetadata(fulcioConfig *FulcioConfig) error {
	checkParse := func(temp string) error {
		t := template.New("").Option("missingkey=error")
		_, err := t.Parse(temp)
		return err
	}

	for _, ciIssuerMetadata := range fulcioConfig.CIIssuerMetadata {
		v := reflect.ValueOf(ciIssuerMetadata.ExtensionTemplates)
		for _, field := range v.Fields() {
			s := field.String()
			err := checkParse(s)
			if err != nil {
				return err
			}
		}

		err := checkParse(ciIssuerMetadata.SubjectAlternativeNameTemplate)
		if err != nil {
			return err
		}
	}
	return nil
}

type Option func(*FulcioConfig) error

// WithBlockedCIDRs configures additional IP addresses or CIDR ranges that the OIDC
// HTTP client dialer will block regardless of issuer type.
func WithBlockedCIDRs(cidrs []string) Option {
	return func(fc *FulcioConfig) error {
		nets, err := parseBlockedCIDRs(cidrs)
		if err != nil {
			return err
		}
		fc.blockedCIDRs = append(fc.blockedCIDRs, nets...)
		return nil
	}
}

func parseBlockedCIDRs(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid blocked CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid blocked IP or CIDR %q", entry)
			}
			if ip4 := ip.To4(); ip4 != nil {
				nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		}
	}
	return nets, nil
}

// Load a config from disk, or use defaults
func Load(configPath string, opts ...Option) (*FulcioConfig, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Logger.Infof("No config at %s, using defaults: %v", configPath, DefaultConfig)
		cfg := *DefaultConfig
		for _, opt := range opts {
			if err := opt(&cfg); err != nil {
				return nil, err
			}
		}
		if err := cfg.prepare(); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return Read(b, opts...)
}

// Read parses the bytes of a config
func Read(b []byte, opts ...Option) (*FulcioConfig, error) {
	config, err := parseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	err = validateConfig(config)
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	if err := config.prepare(); err != nil {
		return nil, err
	}
	return config, nil
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
// TODO: This does not work for domains that end in co.jp or co.uk. We should consider
// using eTLDs, or removing this validation when we can challenge domain ownership.
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

func issuerToChallengeClaim(issType IssuerType, challengeClaim string) string {
	if challengeClaim != "" {
		return challengeClaim
	}
	switch issType {
	case IssuerTypeBuildkiteJob:
		return "sub"
	case IssuerTypeGitLabPipeline:
		return "sub"
	case IssuerTypeEmail:
		return "email"
	case IssuerTypeGithubWorkflow:
		return "sub"
	case IssuerTypeCIProvider:
		return "sub"
	case IssuerTypeCodefreshWorkflow:
		return "sub"
	case IssuerTypeChainguard:
		return "sub"
	case IssuerTypeKubernetes:
		return "sub"
	case IssuerTypeSpiffe:
		return "sub"
	case IssuerTypeURI:
		return "sub"
	case IssuerTypeUsername:
		return "sub"
	default:
		return ""
	}
}

// Inspired by https://github.com/stripe/smokescreen/blob/master/pkg/smokescreen/smokescreen.go
var (
	// currentNetRange is the RFC 1122 / RFC 6890 "Current network" block (0.0.0.0/8).
	currentNetRange = net.IPNet{
		IP:   net.IP{0, 0, 0, 0},
		Mask: net.CIDRMask(8, 32),
	}
	// cgnatRange is the RFC 6598 Shared Address Space (100.64.0.0/10).
	cgnatRange = net.IPNet{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.CIDRMask(10, 32),
	}
	// reservedClassERange is the RFC 1112 Class E / future use and broadcast block (240.0.0.0/4).
	reservedClassERange = net.IPNet{
		IP:   net.IP{240, 0, 0, 0},
		Mask: net.CIDRMask(4, 32),
	}
	// nat64WellKnownRange is the RFC 6052 IPv6-to-IPv4 Well-Known Prefix (64:ff9b::/96).
	nat64WellKnownRange = net.IPNet{
		IP:   net.ParseIP("64:ff9b::"),
		Mask: net.CIDRMask(96, 128),
	}
	// nat64LocalRange is the RFC 8215 Local-Use IPv4/IPv6 Translation Prefix (64:ff9b:1::/48).
	nat64LocalRange = net.IPNet{
		IP:   net.ParseIP("64:ff9b:1::"),
		Mask: net.CIDRMask(48, 128),
	}
	// sixToFourRange is the RFC 3056 6to4 Prefix (2002::/16), which embeds IPv4 addresses.
	sixToFourRange = net.IPNet{
		IP:   net.ParseIP("2002::"),
		Mask: net.CIDRMask(16, 128),
	}
	// teredoRange is the RFC 4380 Teredo Tunneling Prefix (2001::/32), which embeds IPv4 addresses.
	teredoRange = net.IPNet{
		IP:   net.ParseIP("2001::"),
		Mask: net.CIDRMask(32, 128),
	}
)

// getSafeDialer returns a net.Dialer that restricts connections to private, loopback,
// link-local, and custom blocked IP addresses to prevent SSRF vulnerabilities when
// fetching OIDC discovery documents and JWKS endpoints.
// If the configured issuer URL is explicitly a local development hostname, loopback IP
// restrictions are bypassed. If allowPrivate is true (for statically configured OIDCIssuers
// and trusted Kubernetes issuers), private IP ranges are permitted unless matched by blockedCIDRs.
func getSafeDialer(issURL string, allowPrivate bool, blockedCIDRs []*net.IPNet) (*net.Dialer, error) {
	u, err := url.Parse(issURL)
	if err != nil {
		return nil, err
	}
	h := u.Hostname()
	allowLoopback := (h == "127.0.0.1" || h == "localhost" || h == "::1")

	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		// ControlContext is called after the dialer has resolved the hostname via DNS,
		// but before the TCP connection is actually established.
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("failed to parse IP address: %s", host)
			}

			if ip.IsLoopback() {
				if !allowLoopback {
					return fmt.Errorf("connection to loopback IP %s is not allowed", ip.String())
				}
				return nil
			}

			if !ip.IsGlobalUnicast() ||
				currentNetRange.Contains(ip) ||
				reservedClassERange.Contains(ip) ||
				nat64WellKnownRange.Contains(ip) ||
				nat64LocalRange.Contains(ip) ||
				sixToFourRange.Contains(ip) ||
				teredoRange.Contains(ip) {
				return fmt.Errorf("connection to restricted IP %s is not allowed", ip.String())
			}

			for _, blockedNet := range blockedCIDRs {
				if blockedNet.Contains(ip) {
					return fmt.Errorf("connection to restricted IP %s is not allowed", ip.String())
				}
			}

			if !allowPrivate && (ip.IsPrivate() || cgnatRange.Contains(ip)) {
				return fmt.Errorf("connection to private IP %s is not allowed", ip.String())
			}

			return nil
		},
	}, nil
}
