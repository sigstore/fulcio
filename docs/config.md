# Fulcio Configuration

This document describes the Fulcio configuration file: its schema, available fields, and how to configure your own OIDC issuers. For a working example, see the production configuration at [`config/identity/config.yaml`](../config/identity/config.yaml).

For related documentation, see:

- [OIDC Usage in Fulcio](oidc.md) for the OIDC integration guide and how to add a new issuer
- [New IDP Requirements](new-idp-requirements.md) for requirements when adding an identity provider to the public instance
- [OID Info](oid-info.md) for Sigstore OID information used in certificate extensions
- [How Certificate Issuing Works](how-certificate-issuing-works.md) for the end-to-end certificate issuance flow

## Loading the Configuration

Fulcio loads its configuration from a YAML (or JSON) file at startup. The default path is `/etc/fulcio-config/config.yaml`. You can override this with the `--config-path` flag. Note that YAML configs use kebab-case field names (e.g., `oidc-issuers`, `client-id`) while JSON configs use PascalCase (e.g., `OIDCIssuers`, `ClientID`):

```shell
fulcio serve --config-path /path/to/config.yaml
```

If no configuration file exists at the specified path, Fulcio falls back to a hardcoded default configuration that includes Google, GitHub Actions, and the Sigstore Dex instance.

## Top-Level Structure

The configuration file has three top-level sections:

```yaml
oidc-issuers:
  # Exact-match OIDC issuers (the allowlist)
  ...

meta-issuers:
  # Wildcard-pattern issuers for dynamic environments
  ...

ci-issuer-metadata:
  # Claim-to-certificate-extension mappings for CI providers
  ...
```

## OIDC Issuers

The `oidc-issuers` section is a map of issuer URLs to their configuration. Each entry acts as an allowlist entry. Only tokens from issuers defined here (or matching a meta-issuer pattern) are accepted.

### Fields

| Field | YAML Key | JSON Key | Type | Required | Description |
| ------- | ---------- | ---------- | ------ | ---------- | ----------- |
| Issuer URL | _(map key)_ | _(map key)_ | string | Yes | The expected `iss` claim value from the OIDC token. Also used as the map key. |
| `issuer-url` | `issuer-url` | `IssuerURL` | string | Yes | The OIDC issuer URL, used for OIDC discovery. Must match the map key for static issuers. |
| `client-id` | `client-id` | `ClientID` | string | Yes | The expected audience (`aud` claim) of the OIDC token. |
| `type` | `type` | `Type` | string | Yes | The issuer type. Determines how the token is mapped to certificate fields. See [Issuer Types](#issuer-types). |
| `ci-provider` | `ci-provider` | `CIProvider` | string | Conditional | The CI provider name. Required when `type` is `ci-provider`. Must match a key in `ci-issuer-metadata`. |
| `issuer-claim` | `issuer-claim` | `IssuerClaim` | string | No | JSONPath expression to extract the upstream issuer from the token (e.g., `$.federated_claims.connector_id` for Dex). Only valid for `email` type issuers. |
| `subject-domain` | `subject-domain` | `SubjectDomain` | string | Conditional | Domain used for subject validation. Required for `uri` type (must include scheme, e.g., `https://example.com`) and `username` type (plain hostname, e.g., `example.com`). |
| `spiffe-trust-domain` | `spiffe-trust-domain` | `SPIFFETrustDomain` | string | Conditional | The SPIFFE trust domain. Required for `spiffe` type issuers. |
| `challenge-claim` | `challenge-claim` | `ChallengeClaim` | string | No | The token claim used for challenge verification. Defaults to `email` for email issuers and `sub` for all other types. |
| `description` | `description` | `Description` | string | No | A human-readable description of the issuer. |
| `contact` | `contact` | `Contact` | string | No | Contact information (typically an email) for the issuer's team. |
| `ca-cert` | `ca-cert` | `CACert` | string | No | A PEM-encoded CA certificate for trusting the issuer's TLS certificate (useful for internal CAs). |
| `skip-email-verification` | `skip-email-verification` | `SkipEmailVerification` | bool | No | When `true`, skips the `email_verified` claim check. Only use for trusted internal providers (e.g., Microsoft Entra, ADFS) that verify email through their own processes. Defaults to `false`. |

### Issuer Types

| Type | Description | Certificate Subject |
| ---- | ----------- | ------------------- |
| `email` | Standard email-based OIDC (e.g., Google, Dex) | Email address from `email` claim |
| `ci-provider` | Generic CI provider with configurable extension templates | Token subject + mapped claims via `ci-issuer-metadata` |
| `github-workflow` | GitHub Actions (deprecated in favor of `ci-provider`) | Workflow ref as URI |
| `gitlab-pipeline` | GitLab CI (deprecated in favor of `ci-provider`) | Pipeline config as URI |
| `buildkite-job` | Buildkite (deprecated in favor of `ci-provider`) | Job URI |
| `codefresh-workflow` | Codefresh (deprecated in favor of `ci-provider`) | Workflow URI |
| `kubernetes` | Kubernetes service account tokens | Service account subject |
| `spiffe` | SPIFFE ID tokens | SPIFFE ID (validated against trust domain) |
| `uri` | Custom URI-based subjects | URI from `sub` claim (validated against `subject-domain`) |
| `username` | Username-based subjects | Username combined with domain |
| `chainguard-identity` | Chainguard identity tokens | Chainguard subject |

### Example: Email Issuer

```yaml
oidc-issuers:
  https://accounts.google.com:
    issuer-url: https://accounts.google.com
    client-id: sigstore
    type: email
    contact: tac@sigstore.dev
    description: "Google OIDC auth"
```

### Example: Email Issuer with Federated Login (Dex)

```yaml
oidc-issuers:
  https://oauth2.sigstore.dev/auth:
    issuer-url: https://oauth2.sigstore.dev/auth
    client-id: sigstore
    type: email
    issuer-claim: $.federated_claims.connector_id
    contact: tac@sigstore.dev
    description: "dex address for fulcio"
```

### Example: CI Provider Issuer

```yaml
oidc-issuers:
  https://token.actions.githubusercontent.com:
    issuer-url: https://token.actions.githubusercontent.com
    client-id: sigstore
    type: ci-provider
    ci-provider: github-workflow
    contact: tac@sigstore.dev
    description: "GitHub Actions OIDC auth"
```

### Example: Kubernetes Issuer

```yaml
oidc-issuers:
  https://kubernetes.default.svc:
    issuer-url: https://kubernetes.default.svc
    client-id: sigstore
    type: kubernetes
```

When running inside a Kubernetes cluster with the issuer URL `https://kubernetes.default.svc`, Fulcio automatically reads the cluster CA from `/var/run/fulcio/ca.crt` and the service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.

### Example: SPIFFE Issuer

```yaml
oidc-issuers:
  https://spiffe-oidc.example.com:
    issuer-url: https://spiffe-oidc.example.com
    client-id: sigstore
    type: spiffe
    spiffe-trust-domain: example.com
```

### Example: URI Issuer

```yaml
oidc-issuers:
  https://accounts.example.com:
    issuer-url: https://accounts.example.com
    client-id: sigstore
    type: uri
    subject-domain: https://example.com
```

The `subject-domain` must share the same top-level and second-level domain as the `issuer-url`.

### Example: Username Issuer

```yaml
oidc-issuers:
  https://accounts.example.com:
    issuer-url: https://accounts.example.com
    client-id: sigstore
    type: username
    subject-domain: example.com
```

Note that `subject-domain` for username issuers must not include a scheme.

### Example: Issuer with Custom CA Certificate

```yaml
oidc-issuers:
  https://internal-idp.corp.example.com:
    issuer-url: https://internal-idp.corp.example.com
    client-id: sigstore
    type: email
    ca-cert: |
      -----BEGIN CERTIFICATE-----
      MIIBxTCCAWugAwIBAgI...
      -----END CERTIFICATE-----
```

## Meta Issuers

The `meta-issuers` section defines wildcard patterns for dynamic OIDC issuer URLs. This is useful for environments where issuer URLs vary by region, cluster, or tenant (e.g., managed Kubernetes services).

Wildcards use `*` to match one or more alphanumeric characters (including `-` and `_`). The `*` does not match `.` or `/`, so each path segment or subdomain component requires its own wildcard.

Meta issuers support the same fields as regular issuers except that `issuer-url` is not set (it is populated at runtime from the actual token's `iss` claim).

SPIFFE type is not supported for meta issuers because it would create a many-to-one relationship between OIDC issuers and trust domains.

### Example: Kubernetes on AWS EKS

```yaml
meta-issuers:
  https://oidc.eks.*.amazonaws.com/id/*:
    client-id: sigstore
    type: kubernetes
```

This matches URLs like `https://oidc.eks.us-west-2.amazonaws.com/id/B02C93B6A2D30341AD01E1B6D48164CB`.

### Example: Kubernetes on GKE

```yaml
meta-issuers:
  https://container.googleapis.com/v1/projects/*/locations/*/clusters/*:
    client-id: sigstore
    type: kubernetes
```

### Example: Kubernetes on Azure AKS

```yaml
meta-issuers:
  https://*.oic.prod-aks.azure.com/*/*:
    client-id: sigstore
    type: kubernetes
```

### Example: CI Provider Meta Issuer

```yaml
meta-issuers:
  https://token.actions.githubusercontent.com/*:
    client-id: sigstore
    type: ci-provider
    ci-provider: github-workflow
```

## CI Issuer Metadata

The `ci-issuer-metadata` section defines how OIDC token claims from CI providers are mapped to certificate extensions. Each entry is keyed by the CI provider name (matching the `ci-provider` field on issuers).

### Fields

| Field | YAML Key | JSON Key | Type | Description |
| ----- | -------- | -------- | ---- | ----------- |
| `default-template-values` | `default-template-values` | `DefaultTemplateValues` | map[string]string | Default values for template variables. If a claim is not present in the token, the default is used. If a claim has the same name as a default, the claimed value takes priority. |
| `extension-templates` | `extension-templates` | `ExtensionTemplates` | object | Maps certificate extension fields to token claims or Go templates. |
| `subject-alternative-name-template` | `subject-alternative-name-template` | `SubjectAlternativeNameTemplate` | string | Template for the certificate's Subject Alternative Name (SAN). |

### Extension Template Syntax

Extension templates support two forms:

1. **Direct claim reference**: A plain string like `"event_name"` is replaced with the value of that claim from the OIDC token.
2. **Go template**: A string using [Go `text/template`](https://pkg.go.dev/text/template) syntax, e.g., `"{{ .url }}/{{ .repository }}"`. Template variables are populated from token claims merged with `default-template-values`.

### Available Extension Fields

These fields map to Sigstore-specific X.509 certificate extensions (see [OID Info](oid-info.md) for OIDs):

| Extension Field | YAML Key | JSON Key | OID | Description |
| --------------- | -------- | -------- | --- | ----------- |
| BuildSignerURI | `build-signer-uri` | `BuildSignerURI` | 1.3.6.1.4.1.57264.1.9 | Reference to specific build instructions responsible for signing |
| BuildSignerDigest | `build-signer-digest` | `BuildSignerDigest` | 1.3.6.1.4.1.57264.1.10 | Immutable reference to the version of build instructions |
| RunnerEnvironment | `runner-environment` | `RunnerEnvironment` | 1.3.6.1.4.1.57264.1.11 | Platform-hosted or self-hosted build infrastructure |
| SourceRepositoryURI | `source-repository-uri` | `SourceRepositoryURI` | 1.3.6.1.4.1.57264.1.12 | Source repository URL |
| SourceRepositoryDigest | `source-repository-digest` | `SourceRepositoryDigest` | 1.3.6.1.4.1.57264.1.13 | Immutable reference to source code version |
| SourceRepositoryRef | `source-repository-ref` | `SourceRepositoryRef` | 1.3.6.1.4.1.57264.1.14 | Source repository ref (branch/tag) |
| SourceRepositoryIdentifier | `source-repository-identifier` | `SourceRepositoryIdentifier` | 1.3.6.1.4.1.57264.1.15 | Immutable identifier for the source repository |
| SourceRepositoryOwnerURI | `source-repository-owner-uri` | `SourceRepositoryOwnerURI` | 1.3.6.1.4.1.57264.1.16 | Source repository owner URL |
| SourceRepositoryOwnerIdentifier | `source-repository-owner-identifier` | `SourceRepositoryOwnerIdentifier` | 1.3.6.1.4.1.57264.1.17 | Immutable identifier for the source repository owner |
| BuildConfigURI | `build-config-uri` | `BuildConfigURI` | 1.3.6.1.4.1.57264.1.18 | URL to top-level build instructions |
| BuildConfigDigest | `build-config-digest` | `BuildConfigDigest` | 1.3.6.1.4.1.57264.1.19 | Immutable reference to build instructions version |
| BuildTrigger | `build-trigger` | `BuildTrigger` | 1.3.6.1.4.1.57264.1.20 | Event or action that initiated the build |
| RunInvocationURI | `run-invocation-uri` | `RunInvocationURI` | 1.3.6.1.4.1.57264.1.21 | URL to uniquely identify the build execution |
| SourceRepositoryVisibilityAtSigning | `source-repository-visibility-at-signing` | `SourceRepositoryVisibilityAtSigning` | 1.3.6.1.4.1.57264.1.22 | Source repository visibility at signing time |
| DeploymentEnvironment | `deployment-environment` | `DeploymentEnvironment` | 1.3.6.1.4.1.57264.1.23 | Deployment target for the workflow/job |

There are also deprecated GitHub-specific extension fields (`github-workflow-trigger`, `github-workflow-sha`, `github-workflow-name`, `github-workflow-repository`, `github-workflow-ref`) that map to OIDs 1.3.6.1.4.1.57264.1.2 through 1.3.6.1.4.1.57264.1.6. New CI integrations should use the generic extension fields above.

### Example: GitHub Actions

```yaml
ci-issuer-metadata:
  github-workflow:
    default-template-values:
      url: "https://github.com"
      environment: ""
    extension-templates:
      github-workflow-trigger: "event_name"
      github-workflow-sha: "sha"
      github-workflow-name: "workflow"
      github-workflow-repository: "repository"
      github-workflow-ref: "ref"
      build-signer-uri: "{{ .url }}/{{ .job_workflow_ref }}"
      build-signer-digest: "job_workflow_sha"
      runner-environment: "runner_environment"
      source-repository-uri: "{{ .url }}/{{ .repository }}"
      source-repository-digest: "sha"
      source-repository-ref: "ref"
      source-repository-identifier: "repository_id"
      source-repository-owner-uri: "{{ .url }}/{{ .repository_owner }}"
      source-repository-owner-identifier: "repository_owner_id"
      build-config-uri: "{{ .url }}/{{ .workflow_ref }}"
      build-config-digest: "workflow_sha"
      build-trigger: "event_name"
      run-invocation-uri: "{{ .url }}/{{ .repository }}/actions/runs/{{ .run_id }}/attempts/{{ .run_attempt }}"
      source-repository-visibility-at-signing: "repository_visibility"
      deployment-environment: "environment"
    subject-alternative-name-template: "{{ .url }}/{{ .job_workflow_ref }}"
```

### Example: GitLab CI

```yaml
ci-issuer-metadata:
  gitlab-pipeline:
    default-template-values:
      url: "https://gitlab.com"
      environment: ""
    extension-templates:
      build-signer-uri: "https://{{ .ci_config_ref_uri }}"
      build-signer-digest: "ci_config_sha"
      runner-environment: "runner_environment"
      source-repository-uri: "{{ .url }}/{{ .project_path }}"
      source-repository-digest: "sha"
      source-repository-ref: refs/{{if eq .ref_type "branch"}}heads/{{ else }}tags/{{end}}{{ .ref }}
      source-repository-identifier: "project_id"
      source-repository-owner-uri: "{{ .url }}/{{ .namespace_path }}"
      source-repository-owner-identifier: "namespace_id"
      build-config-uri: "https://{{ .ci_config_ref_uri }}"
      build-config-digest: "ci_config_sha"
      build-trigger: "pipeline_source"
      run-invocation-uri: "{{ .url }}/{{ .project_path }}/-/jobs/{{ .job_id }}"
      source-repository-visibility-at-signing: "project_visibility"
      deployment-environment: "environment"
    subject-alternative-name-template: "https://{{ .ci_config_ref_uri }}"
```

## Validation Rules

Fulcio validates the configuration at startup and rejects invalid configs. Key validation rules:

- Every issuer must have a resolvable challenge claim (either explicitly set or derived from the issuer type).
- `spiffe` issuers must have a valid `spiffe-trust-domain`.
- `uri` issuers must have a `subject-domain` with a scheme, and its top-level and second-level domain must match the `issuer-url`.
- `username` issuers must have a `subject-domain` without a scheme, and its top-level and second-level domain must match the `issuer-url`.
- `email` is the only type that supports `issuer-claim`.
- `spiffe` type is not allowed for meta issuers.
- `ca-cert` must be valid PEM if provided.
- All extension templates in `ci-issuer-metadata` must be valid Go templates.
- Meta issuer patterns are compiled to regex with anchors (`^...$`) to prevent issuer injection attacks.

## YAML Anchors

The production config uses YAML anchors to avoid repeating CI provider type strings:

```yaml
define:
  - &github-type "github-workflow"
  - &gitlab-type "gitlab-pipeline"

oidc-issuers:
  https://token.actions.githubusercontent.com:
    issuer-url: https://token.actions.githubusercontent.com
    client-id: sigstore
    type: ci-provider
    ci-provider: *github-type

ci-issuer-metadata:
  *github-type:
    # ...
```

This ensures the `ci-provider` value on the issuer always matches the key in `ci-issuer-metadata`.

## Minimal Configuration Example

A minimal config with a single email issuer:

```yaml
oidc-issuers:
  https://accounts.google.com:
    issuer-url: https://accounts.google.com
    client-id: sigstore
    type: email
```

## Full Configuration Example

See the production configuration at [`config/identity/config.yaml`](../config/identity/config.yaml) for a complete, real-world example covering multiple issuer types, meta issuers, and CI provider metadata.
