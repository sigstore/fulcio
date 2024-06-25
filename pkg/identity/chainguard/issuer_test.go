// Copyright 2024 The Sigstore Authors.
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

package chainguard

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"chainguard.dev/sdk/uidp"
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
		group := uidp.NewUIDP("")
		id := group.NewChild()

		token := &oidc.IDToken{
			Issuer:  "https://iss.example.com",
			Subject: id.String(),
		}
		claims, err := json.Marshal(map[string]interface{}{
			"iss": "https://iss.example.com",
			"sub": id.String(),

			// Actor claims track the identity that was used to assume the
			// Chainguard identity.  In this case, it is the Catalog Syncer
			// service principal.
			"act": map[string]string{
				"iss": "https://iss.example.com/",
				"sub": fmt.Sprintf("catalog-syncer:%s", group.String()),
				"aud": "chainguard",
			},
			"internal": map[string]interface{}{
				"service-principal": "CATALOG_SYNCER",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		withClaims(token, claims)

		identity.Authorize = func(_ context.Context, _ string, _ ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
			return token, nil
		}
		principal, err := issuer.Authenticate(ctx, "token")
		if err != nil {
			t.Fatal(err)
		}

		if principal.Name(ctx) != id.String() {
			t.Fatalf("got unexpected name %s", principal.Name(ctx))
		}
	})
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}
