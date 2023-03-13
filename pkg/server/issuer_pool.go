// Copyright 2023 The Sigstore Authors.
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

package server

import (
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/identity/buildkite"
	"github.com/sigstore/fulcio/pkg/identity/email"
	"github.com/sigstore/fulcio/pkg/identity/github"
	"github.com/sigstore/fulcio/pkg/identity/kubernetes"
	"github.com/sigstore/fulcio/pkg/identity/spiffe"
	"github.com/sigstore/fulcio/pkg/identity/uri"
	"github.com/sigstore/fulcio/pkg/identity/username"
)

func NewIssuerPool(cfg *config.FulcioConfig) identity.IssuerPool {
	var ip identity.IssuerPool
	for _, i := range cfg.OIDCIssuers {
		iss := getIssuer("", i)
		if iss != nil {
			ip = append(ip, iss)
		}
	}
	for meta, i := range cfg.MetaIssuers {
		iss := getIssuer(meta, i)
		if iss != nil {
			ip = append(ip, iss)
		}
	}
	return ip
}

func getIssuer(meta string, i config.OIDCIssuer) identity.Issuer {
	issuerURL := i.IssuerURL
	if meta != "" {
		issuerURL = meta
	}
	switch i.Type {
	case config.IssuerTypeEmail:
		return email.Issuer(issuerURL)
	case config.IssuerTypeGithubWorkflow:
		return github.Issuer(issuerURL)
	case config.IssuerTypeBuildkiteJob:
		return buildkite.Issuer(issuerURL)
	case config.IssuerTypeKubernetes:
		return kubernetes.Issuer(issuerURL)
	case config.IssuerTypeSpiffe:
		return spiffe.Issuer(issuerURL)
	case config.IssuerTypeURI:
		return uri.Issuer(issuerURL)
	case config.IssuerTypeUsername:
		return username.Issuer(issuerURL)
	}
	return nil
}
