# Authorization

## Summary

Fulcio supports optional claims-based authorization that can be configured to restrict certificate issuance based on OIDC token claims. Authorization runs after successful OIDC authentication and before certificate creation, allowing fine-grained access control based on token metadata.

## Overview

The authorization system evaluates configurable rules against OIDC token claims to determine if a certificate request should be approved. This enables scenarios such as:

- Restricting certificate issuance to specific repositories or organizations
- Allowing only certain CI/CD pipelines to obtain certificates
- Implementing custom access control policies based on token claims
- Supporting multi-tenant environments with isolated access

Authorization is **optional** - Fulcio continues to work when no authorization rules are configured.

## How authorization works

```
OIDC Token → Authentication → Authorization → Certificate Issuance
```

1. **Authentication**: OIDC token is validated (configured OIDC Issuers + valid signature)
2. **Authorization**: Token claims are evaluated against configured rules
3. **Certificate Issuance**: Certificate is created if authorization passes or if no authorization rules are defined for the OIDC Issuer

If authorization fails, the request is rejected with HTTP 403 Forbidden.

## Configuration

Authorization rules are configured per OIDC issuer in the Fulcio configuration file:

```yaml
oidc-issuers:
  https://token.actions.githubusercontent.com:
    issuer-url: https://token.actions.githubusercontent.com
    client-id: sigstore
    type: github-workflow
    authorization-rules:
      - name: "Allow specific organization repositories"
        logic: "AND"
        conditions:
          - field: "repository_owner"
            pattern: "^myorg$"
          - field: "repository"
            pattern: "^myorg/(prod-app|staging-app)$"
      - name: "Allow admin user for any repository"
        logic: "AND"
        conditions:
          - field: "actor"
            pattern: "^admin@myorg\\.com$"
```

### Rule structure

- **name**: Descriptive name for the rule (used in logging)
- **logic**: Either "AND" or "OR" to combine conditions
- **conditions**: Array of field/pattern pairs to evaluate

### Condition structure

- **field**: OIDC token claim to evaluate (e.g., "repository", "sub", "email")
- **pattern**: Regular expression pattern to match against the claim value

### Evaluation logic

- **AND logic**: ALL conditions must match for the rule to pass
- **OR logic**: ANY condition can match for the rule to pass
- **Rule evaluation**: If ANY rule passes, authorization succeeds
- **No rules**: If no rules are configured, authorization is skipped

## Common use cases

### 1. Repository-based access control

Restrict certificate issuance to specific GitHub repositories:

```yaml
authorization-rules:
  - name: "Production repositories only"
    logic: "AND"
    conditions:
      - field: "repository_owner"
        pattern: "^myorg$"
      - field: "repository"
        pattern: "^myorg/(api|web|mobile)$"
```

### 2. Organization-wide access

Allow any repository within an organization:

```yaml
authorization-rules:
  - name: "Organization members"
    logic: "AND"
    conditions:
      - field: "repository_owner"
        pattern: "^myorg$"
```

### 3. User-based access control

Allow specific users regardless of repository:

```yaml
authorization-rules:
  - name: "Authorized maintainers"
    logic: "OR"
    conditions:
      - field: "actor"
        pattern: "^(alice|bob|charlie)$"
```

### 4. Environment-based access

Restrict based on deployment environment:

```yaml
authorization-rules:
  - name: "Production deployments"
    logic: "AND"
    conditions:
      - field: "job_workflow_ref"
        pattern: "^myorg/[a-zA-Z0-9._-]{1,100}/.github/workflows/production.yaml@refs/heads/main"
      - field: "repository_owner"
        pattern: "^myorg$"
```

### 5. Multiple rule example

Combine different access patterns:

```yaml
authorization-rules:
  - name: "Production repositories"
    logic: "AND"
    conditions:
      - field: "repository_owner"
        pattern: "^myorg$"
      - field: "repository"
        pattern: "^myorg/(api|web)$"
  - name: "Admin override"
    logic: "AND"
    conditions:
      - field: "actor"
        pattern: "^myorg-admin-bot$"
```

## Security considerations

### Defense in depth

Authorization provides an additional security layer after OIDC authentication:

- **Authentication**: Verifies the token is valid and from a trusted issuer
- **Authorization**: Verifies the authenticated identity should have access
- **Transparency**: All decisions are logged to the certificate transparency log

### Regular expression safety

- Patterns use Go's `regexp` package, which is safe from ReDoS attacks
- Patterns are compiled once at startup for performance
- It is recommended to use anchors (`^` and `$`) to prevent partial matches
- Patterns should be tested thoroughly before deployment

### Token claim validation

- Claims are extracted from authenticated OIDC tokens only
- Authorization cannot be bypassed by manipulating unauthenticated tokens
- All claim values are treated as strings for pattern matching

### Configuration validation and server startup

Fulcio prioritizes security over availability when it comes to authorization configuration:

- **Configuration validation**: All regex patterns and rule structures are validated at startup
- **Fail-secure by design**: Any malformed authorization rules will prevent server startup

This ensures that authorization policies are always correctly applied and prevents accidental security misconfigurations.

### Logging and monitoring

Authorization decisions are logged with structured logging:

```
DEBUG authorization/authorizer.go:130 Authorization passed: rule matched
DEBUG authorization/authorizer.go:145 Authorization denied: no rules matched
```

Monitor these logs to detect:
- Unexpected authorization failures
- Potential security policy violations
- Need for rule adjustments

## Troubleshooting

### Server fails to start with authorization configuration errors

Fulcio uses a fail-secure approach. Any malformed authorization configuration will prevent server startup:

1. **Invalid regex patterns**: Check server startup logs for regex compilation errors
2. **Empty rule names**: Ensure all rules have descriptive names
3. **Invalid logic operators**: Use only "AND" or "OR" (case-insensitive)
4. **Missing conditions**: Each rule must have at least one condition

### Authorization always fails

1. Verify OIDC token contains expected claims
2. Test regex patterns against actual claim values
3. Ensure at least one rule matches your use case
4. Check that field names match actual token claims
4. Start with broad patterns and narrow down
5. Test regex patterns separately before adding to configuration

### Authorization always passes

1. Verify rules are configured in the correct issuer section
2. Check that field names match actual token claims
3. Ensure regex patterns have proper anchors when relevant (`^` and `$`)
5. Test regex patterns separately before adding to configuration

## Integration with Helm charts

When deploying Fulcio with Helm (see [sigstore/helm-charts](https://github.com/sigstore/helm-charts/tree/main/charts/fulcio)), authorization rules can be configured via values:

```yaml
fulcio:
  config:
    contents:
      OIDCIssuers:
        "https://token.actions.githubusercontent.com":
          IssuerURL: "https://token.actions.githubusercontent.com"
          ClientID: "sigstore"
          Type: "github-workflow"
          AuthorizationRules:
            - Name: "Allow specific repositories"
              Logic: "AND"
              Conditions:
                - Field: "repository_owner"
                  Pattern: "^myorg$"
                - Field: "repository"
                  Pattern: "^myorg/allowed-repo$"
```
