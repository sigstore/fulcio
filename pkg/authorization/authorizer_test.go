// Copyright 2025 The Sigstore Authors.
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

package authorization

import (
	"context"
	"testing"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/log"
)

// mockIDTokenClaims is a helper to create a mock token with claims
type mockIDTokenClaims struct {
	claims map[string]interface{}
}

func (m *mockIDTokenClaims) Claims(v interface{}) error {
	// Copy claims to the provided interface (assuming it's a map)
	if claimsMap, ok := v.(*map[string]interface{}); ok {
		*claimsMap = m.claims
	}
	return nil
}

func newMockIDToken(claims map[string]interface{}) IDTokenClaims {
	return &mockIDTokenClaims{claims: claims}
}

func TestDefaultAuthorizer_CompileRules(t *testing.T) {
	authorizer := NewDefaultAuthorizer()

	tests := []struct {
		name        string
		issuerURL   string
		rules       []config.AuthorizationRule
		expectError bool
	}{
		{
			name:      "valid simple rule",
			issuerURL: "https://token.actions.githubusercontent.com",
			rules: []config.AuthorizationRule{
				{
					Name: "Test rule",
					Conditions: []config.AuthorizationCondition{
						{Field: "repository_owner", Pattern: "^example$"},
					},
				},
			},
			expectError: false,
		},
		{
			name:      "valid complex rule with AND logic",
			issuerURL: "https://token.actions.githubusercontent.com",
			rules: []config.AuthorizationRule{
				{
					Name:  "Complex rule",
					Logic: "AND",
					Conditions: []config.AuthorizationCondition{
						{Field: "repository_owner", Pattern: "^example$"},
						{Field: "workflow", Pattern: "^Release$"},
					},
				},
			},
			expectError: false,
		},
		{
			name:      "valid rule with OR logic",
			issuerURL: "https://oidc.spire.example.com",
			rules: []config.AuthorizationRule{
				{
					Name:  "OR rule",
					Logic: "OR",
					Conditions: []config.AuthorizationCondition{
						{Field: "sub", Pattern: "^spiffe://example\\.com/prod/.*"},
						{Field: "sub", Pattern: "^spiffe://example\\.com/staging/.*"},
					},
				},
			},
			expectError: false,
		},
		{
			name:      "invalid regex pattern",
			issuerURL: "https://bad.issuer.com",
			rules: []config.AuthorizationRule{
				{
					Name: "Bad rule",
					Conditions: []config.AuthorizationCondition{
						{Field: "test", Pattern: "[invalid"},
					},
				},
			},
			expectError: true,
		},
		{
			name:      "empty rule name",
			issuerURL: "https://bad.issuer.com",
			rules: []config.AuthorizationRule{
				{
					Name: "",
					Conditions: []config.AuthorizationCondition{
						{Field: "test", Pattern: "valid"},
					},
				},
			},
			expectError: true,
		},
		{
			name:      "no conditions",
			issuerURL: "https://bad.issuer.com",
			rules: []config.AuthorizationRule{
				{
					Name:       "No conditions",
					Conditions: []config.AuthorizationCondition{},
				},
			},
			expectError: true,
		},
		{
			name:      "invalid logic operator",
			issuerURL: "https://bad.issuer.com",
			rules: []config.AuthorizationRule{
				{
					Name:  "Bad logic",
					Logic: "XOR",
					Conditions: []config.AuthorizationCondition{
						{Field: "test", Pattern: "valid"},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "empty rules array",
			issuerURL:   "https://example.com",
			rules:       []config.AuthorizationRule{},
			expectError: false, // Empty rules should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizer.CompileRules(tt.issuerURL, tt.rules)
			if (err != nil) != tt.expectError {
				t.Errorf("CompileRules() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestDefaultAuthorizer_Authorize(t *testing.T) {
	ctx := context.Background()
	// Setup logger for tests
	log.ConfigureLogger("dev")

	authorizer := NewDefaultAuthorizer()

	// Compile test rules
	githubRules := []config.AuthorizationRule{
		{
			Name: "Organization: example",
			Conditions: []config.AuthorizationCondition{
				{Field: "repository_owner", Pattern: "^example$"},
			},
		},
		{
			Name:  "Production workflow",
			Logic: "AND",
			Conditions: []config.AuthorizationCondition{
				{Field: "repository_owner", Pattern: "^example$"},
				{Field: "workflow", Pattern: "^Release$"},
				{Field: "ref", Pattern: "^refs/heads/main$"},
			},
		},
	}

	spiffeRules := []config.AuthorizationRule{
		{
			Name: "SPIFFE Trust domain",
			Conditions: []config.AuthorizationCondition{
				{Field: "sub", Pattern: "^spiffe://example\\.com/.*"},
			},
		},
		{
			Name:  "Production services",
			Logic: "OR",
			Conditions: []config.AuthorizationCondition{
				{Field: "sub", Pattern: "^spiffe://example\\.com/prod/.*"},
				{Field: "sub", Pattern: "^spiffe://example\\.com/staging/.*"},
			},
		},
	}

	err := authorizer.CompileRules("https://token.actions.githubusercontent.com", githubRules)
	if err != nil {
		t.Fatalf("Failed to compile GitHub rules: %v", err)
	}

	err = authorizer.CompileRules("https://oidc.spire.example.com", spiffeRules)
	if err != nil {
		t.Fatalf("Failed to compile SPIFFE rules: %v", err)
	}

	tests := []struct {
		name         string
		issuerConfig config.OIDCIssuer
		claims       map[string]interface{}
		expectError  bool
	}{
		{
			name: "GitHub - example organization passes",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://token.actions.githubusercontent.com",
			},
			claims: map[string]interface{}{
				"iss":              "https://token.actions.githubusercontent.com",
				"sub":              "repo:example/my-app:ref:refs/heads/main",
				"repository_owner": "example",
				"repository":       "example/my-app",
				"workflow":         "CI",
			},
			expectError: false,
		},
		{
			name: "GitHub - production workflow passes",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://token.actions.githubusercontent.com",
			},
			claims: map[string]interface{}{
				"iss":              "https://token.actions.githubusercontent.com",
				"sub":              "repo:example/my-app:ref:refs/heads/main",
				"repository_owner": "example",
				"repository":       "example/my-app",
				"workflow":         "Release",
				"ref":              "refs/heads/main",
			},
			expectError: false,
		},
		{
			name: "GitHub - wrong organization fails",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://token.actions.githubusercontent.com",
			},
			claims: map[string]interface{}{
				"iss":              "https://token.actions.githubusercontent.com",
				"sub":              "repo:evil-org/my-app:ref:refs/heads/main",
				"repository_owner": "evil-org",
				"repository":       "evil-org/my-app",
			},
			expectError: true,
		},
		{
			name: "GitHub - partial production workflow fails",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://token.actions.githubusercontent.com",
			},
			claims: map[string]interface{}{
				"iss":              "https://token.actions.githubusercontent.com",
				"sub":              "repo:other-org/my-app:ref:refs/heads/feature",
				"repository_owner": "other-org", // Different org so first rule won't match
				"workflow":         "Release",
				"ref":              "refs/heads/feature", // Wrong branch for production rule
			},
			expectError: true,
		},
		{
			name: "SPIFFE - trust domain passes",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://oidc.spire.example.com",
			},
			claims: map[string]interface{}{
				"iss": "https://oidc.spire.example.com",
				"sub": "spiffe://example.com/workload/api",
				"aud": "fulcio",
			},
			expectError: false,
		},
		{
			name: "SPIFFE - production service passes",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://oidc.spire.example.com",
			},
			claims: map[string]interface{}{
				"iss": "https://oidc.spire.example.com",
				"sub": "spiffe://example.com/prod/api-service",
				"aud": "fulcio",
			},
			expectError: false,
		},
		{
			name: "SPIFFE - wrong trust domain fails",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://oidc.spire.example.com",
			},
			claims: map[string]interface{}{
				"iss": "https://oidc.spire.example.com",
				"sub": "spiffe://evil.com/workload/api",
				"aud": "fulcio",
			},
			expectError: true,
		},
		{
			name: "No rules configured - should allow",
			issuerConfig: config.OIDCIssuer{
				IssuerURL: "https://no-rules.example.com",
			},
			claims: map[string]interface{}{
				"iss": "https://no-rules.example.com",
				"sub": "test-user",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := newMockIDToken(tt.claims)
			err := authorizer.Authorize(ctx, token, tt.issuerConfig)
			if (err != nil) != tt.expectError {
				t.Errorf("Authorize() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestDefaultAuthorizer_Authorize_EdgeCases(t *testing.T) {
	ctx := context.Background()
	log.ConfigureLogger("dev")

	authorizer := NewDefaultAuthorizer()

	// Test with numeric and boolean claims
	rules := []config.AuthorizationRule{
		{
			Name: "Numeric field test",
			Conditions: []config.AuthorizationCondition{
				{Field: "numeric_field", Pattern: "^123$"},
			},
		},
		{
			Name: "Boolean field test",
			Conditions: []config.AuthorizationCondition{
				{Field: "boolean_field", Pattern: "^true$"},
			},
		},
	}

	err := authorizer.CompileRules("https://test.com", rules)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	tests := []struct {
		name        string
		claims      map[string]interface{}
		expectError bool
	}{
		{
			name: "numeric field matches",
			claims: map[string]interface{}{
				"numeric_field": 123.0, // JSON numbers are float64
				"other_field":   "value",
			},
			expectError: false,
		},
		{
			name: "boolean field matches",
			claims: map[string]interface{}{
				"boolean_field": true,
				"other_field":   "value",
			},
			expectError: false,
		},
		{
			name: "missing required field",
			claims: map[string]interface{}{
				"other_field": "value",
			},
			expectError: true,
		},
		{
			name: "numeric field wrong value",
			claims: map[string]interface{}{
				"numeric_field": 456.0,
				"other_field":   "value",
			},
			expectError: true,
		},
		{
			name: "boolean field wrong value",
			claims: map[string]interface{}{
				"boolean_field": false,
				"other_field":   "value",
			},
			expectError: true,
		},
	}

	issuerConfig := config.OIDCIssuer{IssuerURL: "https://test.com"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := newMockIDToken(tt.claims)
			err := authorizer.Authorize(ctx, token, issuerConfig)
			if (err != nil) != tt.expectError {
				t.Errorf("Authorize() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        config.AuthorizationRule
		expectError bool
	}{
		{
			name: "valid rule",
			rule: config.AuthorizationRule{
				Name: "Test rule",
				Conditions: []config.AuthorizationCondition{
					{Field: "test", Pattern: "valid"},
				},
			},
			expectError: false,
		},
		{
			name: "empty name",
			rule: config.AuthorizationRule{
				Name: "",
				Conditions: []config.AuthorizationCondition{
					{Field: "test", Pattern: "valid"},
				},
			},
			expectError: true,
		},
		{
			name: "no conditions",
			rule: config.AuthorizationRule{
				Name:       "Test rule",
				Conditions: []config.AuthorizationCondition{},
			},
			expectError: true,
		},
		{
			name: "invalid logic",
			rule: config.AuthorizationRule{
				Name:  "Test rule",
				Logic: "INVALID",
				Conditions: []config.AuthorizationCondition{
					{Field: "test", Pattern: "valid"},
				},
			},
			expectError: true,
		},
		{
			name: "valid AND logic",
			rule: config.AuthorizationRule{
				Name:  "Test rule",
				Logic: "and",
				Conditions: []config.AuthorizationCondition{
					{Field: "test", Pattern: "valid"},
				},
			},
			expectError: false,
		},
		{
			name: "valid OR logic",
			rule: config.AuthorizationRule{
				Name:  "Test rule",
				Logic: "or",
				Conditions: []config.AuthorizationCondition{
					{Field: "test", Pattern: "valid"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(tt.rule)
			if (err != nil) != tt.expectError {
				t.Errorf("validateRule() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestValidateCondition(t *testing.T) {
	tests := []struct {
		name        string
		condition   config.AuthorizationCondition
		expectError bool
	}{
		{
			name: "valid condition",
			condition: config.AuthorizationCondition{
				Field:   "test",
				Pattern: "valid",
			},
			expectError: false,
		},
		{
			name: "empty field",
			condition: config.AuthorizationCondition{
				Field:   "",
				Pattern: "valid",
			},
			expectError: true,
		},
		{
			name: "empty pattern",
			condition: config.AuthorizationCondition{
				Field:   "test",
				Pattern: "",
			},
			expectError: true,
		},
		{
			name: "invalid regex",
			condition: config.AuthorizationCondition{
				Field:   "test",
				Pattern: "[invalid",
			},
			expectError: true,
		},
		{
			name: "complex valid regex",
			condition: config.AuthorizationCondition{
				Field:   "email",
				Pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCondition(tt.condition)
			if (err != nil) != tt.expectError {
				t.Errorf("validateCondition() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

// Benchmark tests
func BenchmarkAuthorize_SimpleRule(b *testing.B) {
	ctx := context.Background()
	log.ConfigureLogger("prod") // Reduce log noise in benchmarks

	authorizer := NewDefaultAuthorizer()
	rules := []config.AuthorizationRule{
		{
			Name: "Simple rule",
			Conditions: []config.AuthorizationCondition{
				{Field: "repository_owner", Pattern: "^example$"},
			},
		},
	}

	err := authorizer.CompileRules("https://test.com", rules)
	if err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	issuerConfig := config.OIDCIssuer{IssuerURL: "https://test.com"}
	claims := map[string]interface{}{
		"repository_owner": "example",
		"sub":              "test",
	}
	token := newMockIDToken(claims)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = authorizer.Authorize(ctx, token, issuerConfig)
	}
}

func BenchmarkAuthorize_ComplexRule(b *testing.B) {
	ctx := context.Background()
	log.ConfigureLogger("prod")

	authorizer := NewDefaultAuthorizer()
	rules := []config.AuthorizationRule{
		{
			Name:  "Complex rule",
			Logic: "AND",
			Conditions: []config.AuthorizationCondition{
				{Field: "repository_owner", Pattern: "^example$"},
				{Field: "workflow", Pattern: "^Release$"},
				{Field: "ref", Pattern: "^refs/heads/(main|release/.*)$"},
				{Field: "actor", Pattern: "^[a-z0-9-]+$"},
			},
		},
	}

	err := authorizer.CompileRules("https://test.com", rules)
	if err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	issuerConfig := config.OIDCIssuer{IssuerURL: "https://test.com"}
	claims := map[string]interface{}{
		"repository_owner": "example",
		"workflow":         "Release",
		"ref":              "refs/heads/main",
		"actor":            "release-bot",
		"sub":              "test",
	}
	token := newMockIDToken(claims)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = authorizer.Authorize(ctx, token, issuerConfig)
	}
}
