# Sigstore OID information

## Description

Sigstore maintains its own Private Enterprise Number ([57264](http://oid-info.com/get/1.3.6.1.4.1.57264)) with the Internet
Assigned Numbers Authority to help identify and organize additional metadata in
code signing certificates issued by Fulcio instances. This document aims to
provide a simple directory of values in use with an explanation of their
meaning.

## Requirements to support signing with CI/CD workload identities

In order to support Sigstore code signing with CI/CD based workflow identities the following claims must be included in the OIDC ID Token. See example claim values for each extension in the detailed [Directory](#directory).

Providers MAY choose to emit extension value in other formats to generic examples, and consumers MUST NOT assume the generic example format.

Requirements:

- MUST include `iss` claim for `Issuer` extension.
- MUST include claim to support: `Build Signer URI` that identifies the specific build instructions that are responsible for signing.
- MUST include claim to support: `Runner Environment` that differentiates between builds that took place in platform-hosted cloud infrastructure or customer-hosted infrastructure.

Recommended:

- SHOULD include `iss` that uniquely identifies ID tokens originating from the CI/CD system, e.g. not shared with OIDC OAuth 2.0 tokens for email/username logins.
- SHOULD include claim to support: `Build Signer Digest` which is an immutable reference to a specific version of the build instructions that are responsible for signing.
- SHOULD include claim to support: `Source Repository URI`
- SHOULD include claim to support: `Source Repository Digest`
- SHOULD include claim to support: `Source Repository Ref`
- SHOULD include claim to support: `Source Repository Identifier`
- SHOULD include claim to support: `Source Repository Owner URI`
- SHOULD include claim to support: `Source Repository Owner Identifier`

Nice-to-haves:

- MAY include claim to support: `Build Config URI`
- MAY include claim to support: `Build Config Digest`
- MAY include claim to support: `Build Trigger`
- MAY include claim to support: `Run Invocation URI`
- MAY include claim to support: `Source Repository Visibility At Signing`

## Terminology

- `Identifier`: Immutable resource identifier, e.g. uuid/primary key ID
- `URI`: SHOULD be a fully qualified URL when available. MAY be a mutable resource identifier, e.g. `https://scm.com/example/repository`
  - Fully qualified URL: Complete URL with protocol.
- `Digest`: Output of a cryptographic hash function, e.g. git commit SHA

## Extension values

`1.3.6.1.4.1.57264.1.1` through `1.3.6.1.4.1.57264.1.6` are formatted as raw strings without any DER encoding.

`1.3.6.1.4.1.57264.1.7` is formatted as a DER-encoded string in the SubjectAlternativeName extension, as per RFC 5280 4.2.1.6.

`1.3.6.1.4.1.57264.1.8` through `1.3.6.1.4.1.57264.1.22` are formatted as DER-encoded strings; the ASN.1 tag is
UTF8String (0x0C) and the tag class is universal.

## Directory

Note that all values begin from the root OID 1.3.6.1.4.1.57264 [registered by Sigstore][oid-link].

When adding additional OIDs under the root, please update the above link with the child OID.

GitHub Workflow specific OID extensions have been deprecated in favor of provider generic extensions starting from 1.3.6.1.4.1.57264.1.8.

## 1.3.6.1.4.1.57264.1 | Fulcio

The `.1` is added to the root OID for sigstore for all OIDs set by Fulcio.

### 1.3.6.1.4.1.57264.1.1 | Issuer (deprecated)

This contains the issuer of the OpenID Connect Token that was
presented at the time the code signing certificate was requested to be created.
This corresponds to the `iss` claim for non-federated tokens.

This claim is the URI of the OIDC Identity Provider that digitally signed the
identity token. For example: `https://oidc-issuer.com`.

### 1.3.6.1.4.1.57264.1.2 | GitHub Workflow Trigger (deprecated)

This contains the `event_name` claim from the GitHub OIDC Identity token that
contains the name of the event that triggered the workflow run.
[(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.3 | GitHub Workflow SHA (deprecated)

This contains the `sha` claim from the GitHub OIDC Identity token that contains
the commit SHA that the workflow run was based upon. [(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.4 | GitHub Workflow Name (deprecated)

This contains the `workflow` claim from the GitHub OIDC Identity token that
contains the name of the executed workflow. [(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.5 | GitHub Workflow Repository (deprecated)

This contains the `repository` claim from the GitHub OIDC Identity token that
contains the repository that the workflow run was based upon.
[(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.6 | GitHub Workflow Ref (deprecated)

This contains the `ref` claim from the GitHub OIDC Identity token that contains
the git ref that the workflow run was based upon.
[(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.7 | OtherName SAN

This specifies the username identity in the OtherName Subject Alternative Name, as
defined by [RFC5280 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6).

### 1.3.6.1.4.1.57264.1.8 | Issuer (V2)

This contains the issuer of the OpenID Connect Token that was
presented at the time the code signing certificate was requested to be created.
This corresponds to the `iss` claim for non-federated tokens.

This claim is the URI of the OIDC Identity Provider that digitally signed the
identity token. For example: `https://oidc-issuer.com`.

The difference between this extension and `1.3.6.1.4.1.57264.1.1` is that the extension value
is formatted to the RFC 5280 specification as a DER-encoded string.

### 1.3.6.1.4.1.57264.1.9 | Build Signer URI

Reference to specific build instructions that are responsible for signing. SHOULD be fully qualified. MAY be the same as Build Config URI.

For example a reusable workflow ref in GitHub Actions or a Circle CI Orb name/version. For example: `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.4.0`.

### 1.3.6.1.4.1.57264.1.10 | Build Signer Digest

Immutable reference to the specific version of the build instructions that is responsible for signing. For example: `abc123` git commit SHA.

### 1.3.6.1.4.1.57264.1.11 | Runner Environment

Runner Environment specifying whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure. For example: `[platform]-hosted` and `self-hosted`.

### 1.3.6.1.4.1.57264.1.12 | Source Repository URI

Source repository URL that the build was based on. SHOULD be fully qualified. For example: `https://example.com/owner/repository`.

### 1.3.6.1.4.1.57264.1.13 | Source Repository Digest

Immutable reference to a specific version of the source code that the build
was based upon. For example: `abc123` git commit SHA.

### 1.3.6.1.4.1.57264.1.14 | Source Repository Ref

Source Repository Ref that the build run was based upon. For example: `refs/head/main` git branch or tag.

### 1.3.6.1.4.1.57264.1.15 | Source Repository Identifier

Immutable identifier for the source repository the workflow was based upon. MAY be empty if the Source Repository URI is immutable. For example: `1234` if using a primary key.

### 1.3.6.1.4.1.57264.1.16 | Source Repository Owner URI

Source repository owner URL of the owner of the source repository that the build was based
on. SHOULD be fully qualified. MAY be empty if there is no Source Repository Owner. For example: `https://example.com/owner`

### 1.3.6.1.4.1.57264.1.17 | Source Repository Owner Identifier

Immutable identifier for the owner of the source repository that the workflow was based upon. MAY be empty if there is no Source Repository Owner or Source Repository Owner URI is immutable. For example: `5678` if using a primary key.

### 1.3.6.1.4.1.57264.1.18 | Build Config URI

Build Config URL to the top-level/initiating build instructions. SHOULD be fully qualified. For example: `https://example.com/owner/repository/build-config.yml`.

### 1.3.6.1.4.1.57264.1.19 | Build Config Digest

Immutable reference to the specific version of the top-level/initiating build
instructions. For example: `abc123` git commit SHA.

### 1.3.6.1.4.1.57264.1.20 | Build Trigger

Event or action that initiated the build. For example: `push`.

### 1.3.6.1.4.1.57264.1.21 | Run Invocation URI

Run Invocation URL to uniquely identify the build execution. SHOULD be fully qualified. For example: `https://github.com/example/repository/actions/runs/1536140711/attempts/1`.

### 1.3.6.1.4.1.57264.1.22 | Source Repository Visibility At Signing

Source repository visibility at the time of signing the certificate. MAY be empty if there is no Source Repository Visibility information available. For example: `private` or `public`.

## 1.3.6.1.4.1.57264.2 | Policy OID for Sigstore Timestamp Authority

Not used by Fulcio. This specifies the policy OID for the [timestamp authority](https://github.com/sigstore/timestamp-authority)
that Sigstore operates.

## Mapping OIDC token claims to Fulcio OIDs

| GitHub [(docs)][github-oidc-doc]                                                 | GitLab [(docs)](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html#token-payload) | Buildkite [(docs)](https://buildkite.com/docs/agent/v3/cli-oidc#claims) | Codefresh [(docs)](https://codefresh.io/docs/docs/integrations/oidc-pipelines/) | Fulcio Certificate Extension            | Why / Notes / Questions                                                                                                                                                                |
|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------------------|-----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| aud                                                                              | aud                                                                                               | aud                                                                     | aud                                                                             | N/A                                     | Only used to validate the JWT.                                                                                                                                                         |
| iss                                                                              | iss                                                                                               | iss                                                                     | iss                                                                             | Issuer                                  | This already exists. For example: https://token.actions.githubusercontent.com                                                                                                          |
| exp                                                                              | exp                                                                                               | exp                                                                     | exp                                                                             | N/A                                     | Only used to validate the JWT.                                                                                                                                                         |
| nbf                                                                              | nbf                                                                                               | nbf                                                                     | nbf                                                                             | N/A                                     | Only used to validate the JWT. Optional, as per the OIDC spec                                                                                                                          |
| iat                                                                              | iat                                                                                               | iat                                                                     | iat                                                                             | N/A                                     | Only used to validate the JWT.                                                                                                                                                         |
| server_url + job_workflow_ref                                                    | "https://" + ci_config_ref_uri                                                                    | N/A                                                                     | platform_url + "/build/" +  workflow_id                                         | Build Signer URI                        | Reference to specific build instructions that are responsible for signing. Can be the same as Build Config URI. For example a reusable workflow in GitHub Actions or a Circle CI Orbs. |
| job_workflow_sha                                                                 | ci_config_sha                                                                                     | N/A                                                                     | N/A                                                                             | Build Signer Digest                     | An immutable reference to the specific version of the build instructions that is responsible for signing. May include the digest type followed by the digest, e.g. `sha1:abc123`.      |
| runner_environment                                                               | runner_environment                                                                                | N/A                                                                     | runner_environment                                                              | Runner Environment                      | For platforms to specify whether the build took place in platform-hosted cloud infrastructure or customer-hosted infrastructure. For example: `platform-hosted` and `self-hosted`.     |
| server_url + repository                                                          | server_url + project_path                                                                         | N/A                                                                     | scm_repo_url                                                                    | Source Repository URI                   | Should include a fully qualified repository URL.                                                                                                                                       |
| sha                                                                              | sha                                                                                               | N/A                                                                     | N/A                                                                             | Source Repository Digest                | An immutable reference to a specific version of the source code. May include the digest type followed by the digest, e.g. `sha1:abc123`.                                               |
| ref                                                                              | "ref/heads/" + ref **OR** "ref/tags/" + ref                                                       | N/A                                                                     | scm_ref                                                                         | Source Repository Ref                   | The source ref that the build run was based upon. For example: refs/head/main.                                                                                                         |
| repository_id                                                                    | project_id                                                                                        | N/A                                                                     | N/A                                                                             | Source Repository Identifier            | Stable identifier for the owner of the source repository.                                                                                                                              |
| server_url + repository_owner                                                    | server_url + namespace_path                                                                       | N/A                                                                     | N/A                                                                             | Source Repository Owner URI             | Fully qualified URL for the owner of the source repository.                                                                                                                            |
| repository_owner_id                                                              | namespace_id                                                                                      | N/A                                                                     | N/A                                                                             | Source Repository Owner Identifier      | Stable identifier for the owner of the source repository.                                                                                                                              |
| server_url + workflow_ref                                                        | "https://" + ci_config_ref_uri                                                                    | N/A                                                                     | platform_url + "/api/pipelines/" +  pipeline_id                                 | Build Config URI                        | A reference to the initiating build instructions.                                                                                                                                      |
| workflow_sha                                                                     | ci_config_sha                                                                                     | N/A                                                                     | N/A                                                                             | Build Config Digest                     | An immutable reference to the specific version of the top-level build instructions. May include the digest type followed by the digest, e.g. `sha1:abc123`.                            |
| event_name                                                                       | pipeline_source                                                                                   | N/A                                                                     | N/A                                                                             | Build Trigger                           | The event or action that triggered the build.                                                                                                                                          |
| server_url + repository + "/actions/runs/" + run_id + "/attempts/" + run_attempt | server_url + project_path + "/-/jobs/" + job_id                                                   | N/A                                                                     | platform_url + "/build/" +  workflow_id                                         | Run Invocation URI                      | An immutable identifier that can uniquely identify the build execution                                                                                                                 |
| repository_visibility                                                            | project_visibility                                                                                | N/A                                                                     | N/A                                                                             | Source Repository Visibility At Signing | Source repository visibility at the time of signing the certificate                                                                                                                    |

[github-oidc-doc]: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
[oid-link]: http://oid-info.com/get/1.3.6.1.4.1.57264
