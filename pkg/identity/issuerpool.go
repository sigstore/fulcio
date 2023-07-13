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

package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"
)

type IssuerPool []Issuer

func (p IssuerPool) Authenticate(ctx context.Context, token string, opts ...config.InsecureOIDCConfigOption) (Principal, error) {
	url, err := extractIssuerURL(token)
	if err != nil {
		return nil, err
	}

	for _, issuer := range p {
		if issuer.Match(ctx, url) {
			return issuer.Authenticate(ctx, token, opts...)
		}
	}
	return nil, fmt.Errorf("failed to match issuer URL %s from token with any configured providers", url)
}

func extractIssuerURL(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}

	var payload struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	return payload.Issuer, nil
}
