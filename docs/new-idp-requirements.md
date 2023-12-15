# New IDP Requirements

## Summary

This document describes the minimum requirements for adding a new IDP (Identity Provider) to the Sigstore Public Good Deployment.

Adding a new IDP option to Fulcio helps drive adoption of signing and verification for software artifacts using Sigstore Public Good. Because identity is a critical component of the system, it's important that new IDPs meet the minimum set of requirements to ensure the security and reliability of the ecosystem and users.

You should also reference the [Fulcio - ODIC.md](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md) documentation for additional requirements for the type of IDP you're looking to integrate. The current two likely types of IDPs are:

- `Email` - Email-based OIDC providers use the user's email or the machine identity for service accounts as the subject of the certificate.
- `Workflow` - Workflow-based OIDC providers are used with systems such as CI/CD pipelines, such as GitHub Actions or GitLab CI. These providers will require more onboarding and you should [file an issue](https://github.com/sigstore/fulcio/issues) to discuss the requirements for a specific system.

## Requirements

> The Sigstore Project reserves the right to remove your identity provider from the deployment if it is found to cause technical issues, does not meet the requirements outlined in this document, or if it is deemed to be a security risk to the system.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

A new IDP must meet the following requirements:

- MUST host a `/.well-known/openid-configuration` file that conforms to the OpenID standard for this file.
- MUST have a secure signing key.
- SHOULD have a documented key rotation policy.
- SHOULD have a plan in place for key rotation in the case of compromise.
- SHOULD have a documented signing key storage policy.
- MUST maintain good uptime.
- SHOULD maintain an uptime requirement of `99.9%+`.
- MUST challenge the email address as an OIDC provider for email IDPs.
- MUST prevent identity subject reuse. This requirement is focused on immutable vs mutable identifiers. For example, a person could give up their GitHub username but the GitHub `user_id` would remain the same.
- MUST have a configurable audience (`aud`) for the token, setting the audience to `sigstore`.
- MUST provide a contact during initial configuration that can be used for outreach for issues.
- MUST support the following claims:
  - `issuer`
  - `subject`
  - `audience`
  - `iat` (issued at)
  - `exp` (expiration)
  - Other claims may be required (especially for CI providers). See [Fulcio - ODIC.md](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md)
