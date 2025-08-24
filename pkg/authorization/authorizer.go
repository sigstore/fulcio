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
	"fmt"
	"regexp"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/log"
	"go.uber.org/zap"
)

// IDTokenClaims represents a token that can provide claims
type IDTokenClaims interface {
	Claims(v interface{}) error
}

type Authorizer interface {
	Authorize(ctx context.Context, token IDTokenClaims, issuerConfig config.OIDCIssuer) error
}

type DefaultAuthorizer struct {
	compiledRules map[string][]compiledRule
}

type compiledRule struct {
	name       string
	logic      string
	conditions []compiledCondition
}

type compiledCondition struct {
	field string
	regex *regexp.Regexp
}

func NewDefaultAuthorizer() *DefaultAuthorizer {
	return &DefaultAuthorizer{
		compiledRules: make(map[string][]compiledRule),
	}
}

// CompileRules pre-compiles authorization rules for the given issuer configuration
func (a *DefaultAuthorizer) CompileRules(issuerURL string, rules []config.AuthorizationRule) error {
	if len(rules) == 0 {
		// No rules defined: allow all (default behavior)
		return nil
	}

	var compiledRuleSet []compiledRule
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("invalid rule '%s' for issuer '%s': %w", rule.Name, issuerURL, err)
		}

		var compiledConditions []compiledCondition
		for _, condition := range rule.Conditions {
			regex, err := regexp.Compile(condition.Pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern '%s' in rule '%s' for issuer '%s': %w",
					condition.Pattern, rule.Name, issuerURL, err)
			}
			compiledConditions = append(compiledConditions, compiledCondition{
				field: condition.Field,
				regex: regex,
			})
		}

		compiledRuleSet = append(compiledRuleSet, compiledRule{
			name:       rule.Name,
			logic:      strings.ToUpper(rule.Logic),
			conditions: compiledConditions,
		})
	}

	a.compiledRules[issuerURL] = compiledRuleSet
	return nil
}

// Authorize checks if the token claims satisfy the authorization rules for the issuer
func (a *DefaultAuthorizer) Authorize(ctx context.Context, token IDTokenClaims, issuerConfig config.OIDCIssuer) error {
	logger := log.ContextLogger(ctx)
	issuerURL := issuerConfig.IssuerURL

	// Get compiled rules for this issuer
	rules, exists := a.compiledRules[issuerURL]
	if !exists || len(rules) == 0 {
		// No rules defined for this issuer - allow by default
		logger.Debug("No authorization rules defined for issuer - allowing by default",
			zap.String("issuer", issuerURL))
		return nil
	}

	// Extract all claims from the token
	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		return fmt.Errorf("failed to extract claims from token: %w", err)
	}

	logger.Debug("Evaluating authorization rules",
		zap.String("issuer", issuerURL),
		zap.Int("rule_count", len(rules)),
		zap.String("subject", fmt.Sprintf("%v", claims["sub"])))

	// Evaluate rules (OR logic between rules - any rule passes = authorized)
	for _, rule := range rules {
		if a.evaluateRule(ctx, rule, claims) {
			logger.Debug("Authorization passed: rule matched",
				zap.String("rule_name", rule.name),
				zap.String("issuer", issuerURL))
			return nil
		}
	}

	// No rules passed
	errorMsg := fmt.Sprintf("Authorization failed: no rules matched for issuer %s",
		issuerURL)

	logger.Warn("Authorization denied",
		zap.String("issuer", issuerURL),
		zap.String("subject", fmt.Sprintf("%v", claims["sub"])))

	return fmt.Errorf("%s", errorMsg)
}

func (a *DefaultAuthorizer) evaluateRule(ctx context.Context, rule compiledRule, claims map[string]interface{}) bool {
	logger := log.ContextLogger(ctx)

	if len(rule.conditions) == 0 {
		return true // Empty rule passes
	}

	// If there's only one condition, evaluate it directly
	if len(rule.conditions) == 1 {
		result := a.evaluateCondition(rule.conditions[0], claims)

		claimValue, _ := claims[rule.conditions[0].field].(string)
		logger.Debug("Single condition evaluation",
			zap.String("rule_name", rule.name),
			zap.String("field", rule.conditions[0].field),
			zap.String("pattern", rule.conditions[0].regex.String()),
			zap.String("claim_value", claimValue),
			zap.Bool("result", result))

		return result
	}

	// Multiple conditions - evaluate all and apply logic
	results := make([]bool, len(rule.conditions))

	// Evaluate each condition
	for i, condition := range rule.conditions {
		results[i] = a.evaluateCondition(condition, claims)

		claimValue, _ := claims[condition.field].(string)
		logger.Debug("Condition evaluation",
			zap.String("rule_name", rule.name),
			zap.Int("condition_index", i+1),
			zap.String("field", condition.field),
			zap.String("pattern", condition.regex.String()),
			zap.String("claim_value", claimValue),
			zap.Bool("result", results[i]))
	}

	// Determine logic operator (default to AND if not specified)
	logic := rule.logic
	if logic == "" {
		logic = "AND"
	}

	// Apply logic (AND/OR)
	switch logic {
	case "AND":
		for _, result := range results {
			if !result {
				logger.Debug("Rule failed (AND logic)",
					zap.String("rule_name", rule.name))
				return false
			}
		}
		logger.Debug("Rule passed (AND logic)",
			zap.String("rule_name", rule.name))
		return true
	case "OR":
		for _, result := range results {
			if result {
				logger.Debug("Rule passed (OR logic)",
					zap.String("rule_name", rule.name))
				return true
			}
		}
		logger.Debug("Rule failed (OR logic)",
			zap.String("rule_name", rule.name))
		return false
	default:
		// This should not happen due to validation, but handle gracefully
		logger.Warn("Unknown logic operator, defaulting to AND",
			zap.String("logic_operator", logic),
			zap.String("rule_name", rule.name))
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	}
}

func (a *DefaultAuthorizer) evaluateCondition(condition compiledCondition, claims map[string]interface{}) bool {
	claimValue, exists := claims[condition.field]
	if !exists {
		return false
	}

	var strValue string
	switch v := claimValue.(type) {
	case string:
		strValue = v
	case float64:
		strValue = fmt.Sprintf("%.0f", v)
	case bool:
		strValue = fmt.Sprintf("%v", v)
	default:
		strValue = fmt.Sprintf("%v", v)
	}

	return condition.regex.MatchString(strValue)
}

func validateRule(rule config.AuthorizationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if len(rule.Conditions) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}

	if rule.Logic != "" {
		logic := strings.ToUpper(rule.Logic)
		if logic != "AND" && logic != "OR" {
			return fmt.Errorf("invalid logic operator '%s'. Must be 'AND' or 'OR'", rule.Logic)
		}
	}

	for i, condition := range rule.Conditions {
		if err := validateCondition(condition); err != nil {
			return fmt.Errorf("condition %d: %w", i+1, err)
		}
	}

	return nil
}

func validateCondition(condition config.AuthorizationCondition) error {
	if condition.Field == "" {
		return fmt.Errorf("field cannot be empty")
	}

	if condition.Pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	if _, err := regexp.Compile(condition.Pattern); err != nil {
		return fmt.Errorf("invalid regex pattern '%s': %w", condition.Pattern, err)
	}

	return nil
}
