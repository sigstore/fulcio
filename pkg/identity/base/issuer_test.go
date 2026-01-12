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

package base

import (
	"context"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		description string
		issuerURL   string
		url         string
		expected    bool
	}{
		{
			description: "standard url",
			issuerURL:   "example.com",
			url:         "example.com",
			expected:    true,
		}, {
			description: "url doesn't match",
			issuerURL:   "example.com",
			url:         "something-else.com",
		}, {
			description: "valid regex",
			issuerURL:   "wildcard.*.example.com",
			url:         "wildcard.hello.example.com",
			expected:    true,
		}, {
			description: "invalid regex",
			issuerURL:   "wildcard.*.example.com",
			url:         "wildcard.helloexample.com",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			base := Issuer(test.issuerURL)
			matched := base.Match(context.Background(), test.url)
			if matched != test.expected {
				t.Fatalf("expected %v got %v", test.expected, matched)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	issuer := Issuer("example.com")
	if _, err := issuer.Authenticate(context.Background(), "token"); err == nil {
		t.Fatal("expected error on authenticate, BaseIssuer shouldn't implement Authenticate")
	}
}
