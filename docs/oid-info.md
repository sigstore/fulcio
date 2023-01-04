# Sigstore OID information

## Description

Sigstore maintains its own Private Enterprise Number (57264) with the Internet
Assigned Numbers Authority to help identify and organize additional metadata in
code signing certificates issued by Fulcio instances. This document aims to
provide a simple directory of values in use with an explanation of their
meaning.

## Directory

Note that all values begin from the root OID 1.3.6.1.4.1.57264 [registered by Sigstore][oid-link].

When adding additional OIDs under the root, please update the above link with the child OID.

## 1.3.6.1.4.1.57264.1 | Fulcio

The `.1` is added to the root OID for sigstore for all OIDs set by Fulcio.

### 1.3.6.1.4.1.57264.1.1 | Issuer

This contains the `issuer` claim from the OIDC Identity Token that was
presented at the time the code signing certificate was requested to be created.
This claim is the URI of the OIDC Identity Provider that digitally signed the
identity token. For example: https://token.actions.githubusercontent.com.

### 1.3.6.1.4.1.57264.3.1 | Source URI

Should include a fully qualified source repository URL that the build was based
on.

### 1.3.6.1.4.1.57264.3.2 | Source Digest

An immutable reference to a specific version of the source code that the build
was based upon. Should include the digest type followed by the digest, e.g.
`sha1:abc123`.

### 1.3.6.1.4.1.57264.3.3 | Source Ref

The source ref that the build run was based upon. For example: `refs/head/main`.

### 1.3.6.1.4.1.57264.3.4 | Build Config URI

A reference to the initiating build instructions.

### 1.3.6.1.4.1.57264.3.5 | Build Config Digest

An immutable reference to the specific version of the top-level build
instructions. Should include the digest type followed by the digest, e.g.
`sha1:abc123`.

### 1.3.6.1.4.1.57264.3.6 | Build Siger URI

Reference to specific build instructions that are responsible for signing. Can be the same as Build Config URI. For example a reusable workflow in GitHub Actions or a Circle CI Orbs.


### 1.3.6.1.4.1.57264.3.7 | Build Siger Digest

An immutable reference to the specific version of the build instructions that is responsible for signing. Should include the digest type followed by the digest, e.g. `sha1:abc123`.


### 1.3.6.1.4.1.57264.3.8 | Build Trigger

The event or action that triggered the build.
### 1.3.6.1.4.1.57264.3.9 | Runner Environment

For platforms to specify whether the build took place in platform-hosted cloud infrastructure or customer-hosted infrastructure. For example: `platform-hosted` and `self-hosted`.

### 1.3.6.1.4.1.57264.1.7 | OtherName SAN

This specifies the username identity in the OtherName Subject Alternative Name, as
defined by [RFC5280 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6).

## 1.3.6.1.4.1.57264.2 | Policy OID for Sigstore Timestamp Authority

Not used by Fulcio. This specifies the policy OID for the [timestamp authority](https://github.com/sigstore/timestamp-authority)
that Sigstore operates.

## Mapping OIDC token claims to Fulcio OIDs

| GitHub [(docs)][github-oidc-doc] | GitLab | CircleCI | Buildkite | Fulcio Certificate Extension | Why / Notes / Questions                                                                                                                                                                |
|--------------------|--------|----------|-----------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| aud                | ??     | ??       | ??        | N/A                          | Only used to validate the JWT.                                                                                                                                                         |
| iss                | ??     | ??       | ??        | Issuer                       | This already exists. For example: https://token.actions.githubusercontent.com                                                                                                          |
| exp                | ??     | ??       | ??        | N/A                          | Only used to validate the JWT.                                                                                                                                                         |
| nbf                | ??     | ??       | ??        | N/A                          | Only used to validate the JWT.                                                                                                                                                         |
| iat                | ??     | ??       | ??        | N/A                          | Only used to validate the JWT.                                                                                                                                                         |
| repository         | ??     | ??       | ??        | Source URI                   | Should include a fully qualified repository URL.                                                                                                                                       |
| sha                | ??     | ??       | ??        | Source Digest                | An immutable reference to a specific version of the source code. Should include the digest type followed by the digest, e.g. `sha1:abc123`.                                            |
| ref                | ??     | ??       | ??        | Source Ref                   | The source ref that the build run was based upon. For example: refs/head/main.                                                                                                         |
| workflow_ref       | ??     | ??       | ??        | Build Config URI             | A reference to the initiating build instructions.                                                                                                                                      |
| workflow_sha       | ??     | ??       | ??        | Build Config Digest          | An immutable reference to the specific version of the top-level build instructions. Should include the digest type followed by the digest, e.g. `sha1:abc123`.                         |
| job_workflow_ref   | ??     | ??       | ??        | Build Signer URI             | Reference to specific build instructions that are responsible for signing. Can be the same as Build Config URI. For example a reusable workflow in GitHub Actions or a Circle CI Orbs. |
| job_workflow_sha   | ??     | ??       | ??        | Build Signer Digest          | An immutable reference to the specific version of the build instructions that is responsible for signing. Should include the digest type followed by the digest, e.g. `sha1:abc123`.   |
| event_name         | ??     | ??       | ??        | Build Trigger                | The event or action that triggered the build.                                                                                                                                          |
| runner_environment | ??     | ??       | ??        | Runner Environment           | For platforms to specify whether the build took place in platform-hosted cloud infrastructure or customer-hosted infrastructure. For example: `platform-hosted` and `self-hosted`.     |

[github-oidc-doc]: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
[oid-link]: http://oid-info.com/get/1.3.6.1.4.1.57264
