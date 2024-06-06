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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru"
	fulciogrpc "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/yaml.v3"
)

const defaultOIDCDiscoveryTimeout = 10 * time.Second

// All hostnames for subject and issuer OIDC claims must have at least a
// top-level and second-level domain
const minimumHostnameLength = 2

type verifierWithConfig struct {
	*oidc.IDTokenVerifier
	*oidc.Config
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

	// verifiers is a fixed mapping from our OIDCIssuers to their OIDC verifiers.
	verifiers map[string][]*verifierWithConfig
	// lru is an LRU cache of recently used verifiers for our meta issuers.
	lru *lru.TwoQueueCache
}

type OIDCIssuer struct {
	// The expected issuer of an OIDC token
	IssuerURL string `json:"IssuerURL,omitempty" yaml:"issuer-url,omitempty"`
	// The expected client ID of the OIDC token
	ClientID string `json:"ClientID" yaml:"client-id,omitempty"`
	// Used to determine the subject of the certificate and if additional
	// certificate values are needed
	Type IssuerType `json:"Type" yaml:"type,omitempty"`
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
}

func metaRegex(issuer string) (*regexp.Regexp, error) {
	// Quote all of the "meta" characters like `.` to avoid
	// those literal characters in the URL matching any character.
	// This will ALSO quote `*`, so we replace the quoted version.
	quoted := regexp.QuoteMeta(issuer)

	// Replace the quoted `*` with a regular expression that
	// will match alpha-numeric parts with common additional
	// "special" characters.
	replaced := strings.ReplaceAll(quoted, regexp.QuoteMeta("*"), "[-_a-zA-Z0-9]+")

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
		re, err := metaRegex(meta)
		if err != nil {
			continue // Shouldn't happen, we check parsing the config
		}
		if re.MatchString(issuerURL) {
			// If it matches, then return a concrete OIDCIssuer
			// configuration for this issuer URL.
			return OIDCIssuer{
				IssuerURL:     issuerURL,
				ClientID:      iss.ClientID,
				Type:          iss.Type,
				IssuerClaim:   iss.IssuerClaim,
				SubjectDomain: iss.SubjectDomain,
				IsCiProvider:  iss.IsCiProvider,
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
	untyped, ok := fc.lru.Get(issuerURL)
	if ok {
		v := untyped.([]*verifierWithConfig)
		for _, c := range v {
			if reflect.DeepEqual(c.Config, cfg) {
				return c.IDTokenVerifier, true
			}
		}
	}

	// If this issuer hasn't been recently used, or we have special config options, then create a new verifier
	// and add it to the LRU cache.

	ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCDiscoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Logger.Warnf("Failed to create provider for issuer URL %q: %v", issuerURL, err)
		return nil, false
	}

	vwf := &verifierWithConfig{provider.Verifier(cfg), cfg}
	if untyped == nil {
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
			Issuer:            &fulciogrpc.OIDCIssuer_IssuerUrl{IssuerUrl: cfgIss.IssuerURL},
			Audience:          cfgIss.ClientID,
			SpiffeTrustDomain: cfgIss.SPIFFETrustDomain,
			ChallengeClaim:    issuerToChallengeClaim(cfgIss, cfgIss.ChallengeClaim),
		}
		issuers = append(issuers, issuer)
	}

	for metaIss, cfgIss := range fc.MetaIssuers {
		issuer := &fulciogrpc.OIDCIssuer{
			Issuer:            &fulciogrpc.OIDCIssuer_WildcardIssuerUrl{WildcardIssuerUrl: metaIss},
			Audience:          cfgIss.ClientID,
			SpiffeTrustDomain: cfgIss.SPIFFETrustDomain,
			ChallengeClaim:    issuerToChallengeClaim(cfgIss, cfgIss.ChallengeClaim),
		}
		issuers = append(issuers, issuer)
	}

	return issuers
}

func (fc *FulcioConfig) prepare() error {
	if _, ok := fc.GetIssuer("https://kubernetes.default.svc"); ok {
		// Add the Kubernetes cluster's CA to the system CA pool, and to
		// the default transport.
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		const k8sCA = "/var/run/fulcio/ca.crt"
		certs, err := os.ReadFile(k8sCA)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			return fmt.Errorf("unable to append certs")
		}

		t := originalTransport.(*http.Transport).Clone()
		t.TLSClientConfig.RootCAs = rootCAs
		http.DefaultTransport = t
	} else {
		// If we parse a config that doesn't include a cluster issuer
		// signed with the cluster'sCA, then restore the original transport
		// (in case we overwrote it)
		http.DefaultTransport = originalTransport
	}

	fc.verifiers = make(map[string][]*verifierWithConfig, len(fc.OIDCIssuers))
	for _, iss := range fc.OIDCIssuers {
		ctx, cancel := context.WithTimeout(context.Background(), defaultOIDCDiscoveryTimeout)
		defer cancel()
		provider, err := oidc.NewProvider(ctx, iss.IssuerURL)
		if err != nil {
			log.Logger.Errorf("error creating provider for issuer URL %q: %v", iss.IssuerURL, err)
		} else {
			cfg := &oidc.Config{ClientID: iss.ClientID}
			fc.verifiers[iss.IssuerURL] = []*verifierWithConfig{{provider.Verifier(cfg), cfg}}
		}
	}

	cache, err := lru.New2Q(100 /* size */)
	if err != nil {
		return fmt.Errorf("lru: %w", err)
	}
	fc.lru = cache
	return nil
}

// I would like to remove this completely, to be able to add or remove
// oidc providers only by updating the config.yaml file.
type IssuerType string

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

		if issuerToChallengeClaim(issuer, issuer.ChallengeClaim) == "" {
			return errors.New("issuer missing challenge claim")
		}
	}

	for _, metaIssuer := range conf.MetaIssuers {
		if metaIssuer.Type == IssuerTypeSpiffe {
			// This would establish a many to one relationship for OIDC issuers
			// to trust domains so we fail early and reject this configuration.
			return errors.New("SPIFFE meta issuers not supported")
		}

		if issuerToChallengeClaim(metaIssuer, metaIssuer.ChallengeClaim) == "" {
			return errors.New("issuer missing challenge claim")
		}
	}

	return nil
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

var originalTransport = http.DefaultTransport

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

// Load a config from disk, or use defaults
func Load(configPath string) (*FulcioConfig, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Logger.Infof("No config at %s, using defaults: %v", configPath, DefaultConfig)
		config := DefaultConfig
		if err := config.prepare(); err != nil {
			return nil, err
		}
		return config, nil
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return Read(b)
}

// Read parses the bytes of a config
func Read(b []byte) (*FulcioConfig, error) {
	config, err := parseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
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
