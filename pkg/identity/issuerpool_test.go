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
	"crypto/x509"
	"errors"
	"testing"
)

type testPrincipal struct {
	name string
}

func (p testPrincipal) Name(ctx context.Context) string {
	return p.name
}

func (p testPrincipal) Embed(ctx context.Context, cert *x509.Certificate) error {
	return nil
}

type testIssuer struct {
	match func(context.Context, string) bool
	auth  func(context.Context, string) (Principal, error)
}

func (i testIssuer) Match(ctx context.Context, url string) bool {
	return i.match(ctx, url)
}

func (i testIssuer) Authenticate(ctx context.Context, token string) (Principal, error) {
	return i.auth(ctx, token)
}

func TestIssuerPool(t *testing.T) {
	var (
		// Example principals
		alice = testPrincipal{`alice`}
		bob   = testPrincipal{`bob`}

		// Example issuers
		bobIfExampleCom = testIssuer{
			match: func(_ context.Context, url string) bool {
				return url == `example.com`
			},
			auth: func(context.Context, string) (Principal, error) {
				return bob, nil
			},
		}
		aliceIfOtherCom = testIssuer{
			match: func(_ context.Context, url string) bool {
				return url == `other.com`
			},
			auth: func(context.Context, string) (Principal, error) {
				return alice, nil
			},
		}
		matchThenRejectAll = testIssuer{
			match: func(context.Context, string) bool {
				return true
			},
			auth: func(context.Context, string) (Principal, error) {
				return nil, errors.New(`boooooo`)
			},
		}

		// Example tokens
		// iss == example.com
		exampleToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlLmNvbSJ9.eBJFurm45FSlxt9c7r339xkQC7yqn2O9SlBldCFAQhk`
		// iss == other.com
		otherToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJvdGhlci5jb20ifQ.GtTvBmBvm0kPIfBctKDD1GDavmtlQXBQIDjGg6k2kOA`
		// iss == bad.com
		badToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJiYWQuY29tIn0.aW-Zyc3JTnqI0uqc1VzNY9_5BhmhXmUksGaFEiiZCHU`
		// bad format token
		badFormatToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.??.aW-Zyc3JTnqI0uqc1VzNY9_5BhmhXmUksGaFEiiZCHU`
	)

	tests := map[string]struct {
		Pool              IssuerPool
		Token             string
		ExpectedPrincipal Principal
		WantErr           bool
	}{
		`example.com only pool should allow example.com tokens`: {
			Pool:              IssuerPool{bobIfExampleCom},
			Token:             exampleToken,
			ExpectedPrincipal: bob,
			WantErr:           false,
		},
		`example.com only pool should not allow other.com tokens`: {
			Pool:    IssuerPool{bobIfExampleCom},
			Token:   otherToken,
			WantErr: true,
		},
		`example.com and other.com pool should match other.com token to alice`: {
			Pool:              IssuerPool{bobIfExampleCom, aliceIfOtherCom},
			Token:             otherToken,
			ExpectedPrincipal: alice,
			WantErr:           false,
		},
		`example.com and other.com pool should match example.com token to bob`: {
			Pool:              IssuerPool{bobIfExampleCom, aliceIfOtherCom},
			Token:             exampleToken,
			ExpectedPrincipal: bob,
			WantErr:           false,
		},
		`example.com and other.com pool should reject bad.com token`: {
			Pool:    IssuerPool{bobIfExampleCom, aliceIfOtherCom},
			Token:   badToken,
			WantErr: true,
		},
		`example.com and other.com pool should reject badly formatted token`: {
			Pool:    IssuerPool{bobIfExampleCom, aliceIfOtherCom},
			Token:   badFormatToken,
			WantErr: true,
		},
		`empty pool should never authenticate`: {
			Pool:    IssuerPool{},
			Token:   exampleToken,
			WantErr: true,
		},
		`match then reject all pool should never authenticate`: {
			Pool:    IssuerPool{matchThenRejectAll},
			Token:   exampleToken,
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			principal, err := test.Pool.Authenticate(ctx, test.Token)
			if err != nil {
				if !test.WantErr {
					t.Error("Didn't expect error", err)
				}
			} else {
				if principal != test.ExpectedPrincipal {
					t.Errorf("Got principal %s, but wanted %s", principal.Name(ctx), test.ExpectedPrincipal.Name(ctx))
				}
			}
		})
	}
}

func TestExtractIssuerURL(t *testing.T) {
	tests := map[string]struct {
		Token       string
		ExpectedURL string
		WantErr     bool
	}{
		`issuer example.com`: {
			// Valid token (HS256 with `derp` secret) and iss = example.com
			Token:       `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlLmNvbSJ9.LGkuVtRymNgdZFn4v_jRJCJVwdt1wZDw588tbXC8VTU`,
			ExpectedURL: `example.com`,
			WantErr:     false,
		},
		`no issuer claim`: {
			// Valid JWT but no `iss` claim. Claims are {"foo": "bar"}.
			Token:   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.kOu-Qu-GoCH3G70LKrm_W9DJj2MpF4C5QweznLgGZgc`,
			WantErr: true,
		},
		`Not enough token parts`: {
			// Has 2 parts instead of 3
			Token:   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ`,
			WantErr: true,
		},
		`Too many token parts`: {
			// Has 4 parts instead of 3
			Token:   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.eyJmb28iOiJiYXIifQ.eyJmb28iOiJiYXIifQ`,
			WantErr: true,
		},
		`Bad claims base64 encoding`: {
			// ??? are illegal base64 url safe characters
			Token:   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.???.kOu-Qu-GoCH3G70LKrm_W9DJj2MpF4C5QweznLgGZgc`,
			WantErr: true,
		},
		`Bad claims JSON format`: {
			// fXs decodes to `}{` which is note valid JSON
			Token:   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fXs.kOu-Qu-GoCH3G70LKrm_W9DJj2MpF4C5QweznLgGZgc`,
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotURL, err := extractIssuerURL(test.Token)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
			} else {
				if gotURL != test.ExpectedURL {
					t.Errorf("Wanted %s and got %s for issuer url", test.ExpectedURL, gotURL)
				}
			}
		})
	}
}
