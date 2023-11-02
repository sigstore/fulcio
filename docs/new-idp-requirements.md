# New IDP Requirements

## Summary

This document describes the minimum requirements for adding a new IDP (Identity Provider) to the Sigstore Public Good Deployment.

## Requirements

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

A new IDP must meet the following requirements:

- MUST host a `/.well-known/openid-configuration` file.
- MUST have a documented key rotation policy.
- MUST have a documented signing key storage policy.
- MUST maintain an uptime requirement of `99.5%`.
- MUST challenge the email address as an OIDC provider.
- MUST prevent identity subject reuse.
- MUST have a configurable audience (`aud`) for the token, setting the audience to `sigstore`.
- MUST support the following claims:
  - `issuer`
  - `subject`
  - `audience`
  - `issued at`
  - `expiration`
