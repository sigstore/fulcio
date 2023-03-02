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

package uri

import (
	"context"

	"github.com/sigstore/fulcio/pkg/identity"
)

type uriIssuer struct {
	issuerURL string
}

func Issuer(issuerURL string) identity.Issuer {
	return &uriIssuer{issuerURL: issuerURL}
}

func (e *uriIssuer) Authenticate(ctx context.Context, token string) (identity.Principal, error) {
	idtoken, err := identity.Authorize(ctx, token)
	if err != nil {
		return nil, err
	}
	return PrincipalFromIDToken(ctx, idtoken)
}

// Match checks if this issuer can authenticate tokens from a given issuer URL
func (e *uriIssuer) Match(ctx context.Context, url string) bool {
	return url == e.issuerURL
}
