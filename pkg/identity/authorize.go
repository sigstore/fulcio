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

package identity

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
)

// We do this to bypass needing actual OIDC tokens for unit testing.
var Authorize = actualAuthorize

func actualAuthorize(ctx context.Context, token string) (*oidc.IDToken, error) {
	issuer, err := extractIssuerURL(token)
	if err != nil {
		return nil, err
	}

	verifier, ok := config.FromContext(ctx).GetVerifier(issuer)
	if !ok {
		return nil, fmt.Errorf("unsupported issuer: %s", issuer)
	}
	return verifier.Verify(ctx, token)
}
