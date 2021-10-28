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
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/sigstore/fulcio/pkg/log"
)

type FulcioConfig struct {
	OIDCIssuers map[string]OIDCIssuer
}

type OIDCIssuer struct {
	IssuerURL   string
	ClientID    string
	Type        IssuerType
	IssuerClaim string `json:"IssuerClaim,omitempty"`
}

type IssuerType string

const (
	IssuerTypeEmail          = "email"
	IssuerTypeGithubWorkflow = "github-workflow"
	IssuerTypeKubernetes     = "kubernetes"
	IssuerTypeSpiffe         = "spiffe"
)

func ParseConfig(b []byte) (FulcioConfig, error) {
	cfg := FulcioConfig{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return FulcioConfig{}, err
	}
	return cfg, nil
}

var DefaultConfig = FulcioConfig{
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

func Config() FulcioConfig {
	if config == nil {
		log.Logger.Panic("Config() called without loading config first")
	}
	return *config
}

// Load a config from disk, or use defaults
func Load(configPath string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Logger.Infof("No config at %s, using defaults: %v", configPath, DefaultConfig)
		config = &DefaultConfig
		return nil
	}
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}
	cfg, err := ParseConfig(b)
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

	config = &cfg
	log.Logger.Infof("Loaded config %v from %s", cfg, configPath)
	return nil
}
