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
	"io/ioutil"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/log"
)

type FulcioConfig struct {
	OIDCIssuers map[string]OIDCIssuer

	// TODO(mattmoor): We want to match these kinds of meta-URLs.
	// https://oidc.eks.us-west-2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB
	// https://container.googleapis.com/v1/projects/mattmoor-credit/locations/us-west1-b/clusters/tenant-cluster

	verifiers map[string]*oidc.IDTokenVerifier
}

type OIDCIssuer struct {
	IssuerURL   string
	ClientID    string
	Type        IssuerType
	IssuerClaim string `json:"IssuerClaim,omitempty"`
}

// GetIssuer looks up the issuer configuration for an `issuerURL`
// coming from an incoming OIDC token.  If no matching configuration
// is found, then it returns `false`.
func (fc *FulcioConfig) GetIssuer(issuerURL string) (OIDCIssuer, bool) {
	iss, ok := fc.OIDCIssuers[issuerURL]

	// TODO(mattmoor): Add support for meta-URLs.

	return iss, ok
}

// GetVerifier fetches a token verifier for the given `issuerURL`
// coming from an incoming OIDC token.  If no matching configuration
// is found, then it returns `false`.
func (fc *FulcioConfig) GetVerifier(issuerURL string) (*oidc.IDTokenVerifier, bool) {
	v, ok := fc.verifiers[issuerURL]

	// TODO(mattmoor): Add an LRU cache of verifiers for issuers that match one of our meta-URLs

	return v, ok
}

type IssuerType string

const (
	IssuerTypeEmail          = "email"
	IssuerTypeGithubWorkflow = "github-workflow"
	IssuerTypeKubernetes     = "kubernetes"
	IssuerTypeSpiffe         = "spiffe"
)

func parseConfig(b []byte) (cfg *FulcioConfig, err error) {
	cfg = &FulcioConfig{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
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

var config *FulcioConfig
var originalTransport = http.DefaultTransport

func Config() *FulcioConfig {
	if config == nil {
		log.Logger.Panic("Config() called without loading config first")
	}
	return config
}

// Load a config from disk, or use defaults
func Load(configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Logger.Infof("No config at %s, using defaults: %v", configPath, DefaultConfig)
		config = DefaultConfig
		return nil
	}
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}
	cfg, err := parseConfig(b)
	if err != nil {
		return err
	}

	if _, ok := cfg.OIDCIssuers["https://kubernetes.default.svc"]; ok {
		// Add the Kubernetes cluster's CA to the system CA pool, and to
		// the default transport.
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		const k8sCA = "/var/run/fulcio/ca.crt"
		certs, err := ioutil.ReadFile(k8sCA)
		if err != nil {
			return err
		}
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			return err
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

	// Eagerly populate the verifiers for the OIDCIssuers.
	cfg.verifiers = make(map[string]*oidc.IDTokenVerifier, len(cfg.OIDCIssuers))
	for _, iss := range cfg.OIDCIssuers {
		provider, err := oidc.NewProvider(context.Background(), iss.IssuerURL)
		if err != nil {
			return err
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: iss.ClientID})
		cfg.verifiers[iss.IssuerURL] = verifier
	}

	config = cfg
	log.Logger.Infof("Loaded config %v from %s", cfg, configPath)
	return nil
}
