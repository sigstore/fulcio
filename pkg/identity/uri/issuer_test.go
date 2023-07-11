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
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

func TestIssuer(t *testing.T) {
	ctx := context.Background()
	url := "test-issuer-url"
	issuer := Issuer(url)

	// test the Match function
	t.Run("match", func(t *testing.T) {
		if matches := issuer.Match(ctx, url); !matches {
			t.Fatal("expected url to match but it doesn't")
		}
		if matches := issuer.Match(ctx, "some-other-url"); matches {
			t.Fatal("expected match to fail but it didn't")
		}
	})

	t.Run("authenticate", func(t *testing.T) {
		token := &oidc.IDToken{
			Issuer:  "https://accounts.example.com",
			Subject: "https://example.com/users/1",
		}

		cfg := &config.FulcioConfig{
			OIDCIssuers: map[string]config.OIDCIssuer{
				"https://accounts.example.com": {
					IssuerURL:     "https://accounts.example.com",
					ClientID:      "sigstore",
					SubjectDomain: "https://example.com",
					Type:          config.IssuerTypeURI,
				},
			},
		}
		ctx := config.With(context.Background(), cfg)

		identity.Authorize = func(_ context.Context, _ string, _ ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
			return token, nil
		}
		principal, err := issuer.Authenticate(ctx, "token")
		if err != nil {
			t.Fatal(err)
		}

		if principal.Name(ctx) != "https://example.com/users/1" {
			t.Fatalf("got unexpected name %s", principal.Name(ctx))
		}
	})
}
