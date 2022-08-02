# Security Model

Fulcio assumes that a valid OIDC token is a sufficient "proof of ownership" of
an email address.

To mitigate against OIDC compromise, Fulcio appends certificates to an immutable,
append-only cryptographically verifiable transparency log.

- Fulcio MUST publish all certificates to the log.
- Clients MUST NOT trust certificates that are not in the log.

As a result users can detect any mis-issued certificates, either due to the CA
acting maliciously or a compromised OIDC identity provider.

Combined with [Rekor's](https://github.com/sigstore/rekor) signature transparency, artifacts signed with
compromised accounts can be identified.

## Revocation, Rotation and Expiry

Fulcio is designed to avoid the need for revocation of certificates. The Sigstore
ecosystem is designed to avoid the need for maintainers to frequently re-sign artifacts.

### Long-term Certificates

These certificates are typically valid for years.  All artifacts must be
re-signed with a new certficate before an old certificate expires. Typically this requires
long deprecation periods, dual-signing and planned rotations.

There are a couple problems with this approach:

1. It requires that users can maintain access to private keys and keep them secure over
   long periods of time.
2. Revocation doesn't scale well.

### Fulcio's Model

Fulcio is designed to avoid revocation, by issuing *short-lived certificates*.
What really matters for code signing is to know that an artifact was signed
while the certificate was valid.

Sigstore accomplishes this with a tranpsarency log called
[Rekor](https://github.com/sigstore/rekor). A verifier should check that the
inclusion time in the log was during the certificate's validity period.

An entry in Rekor provides a single-party attestation that a piece of data
existed prior to a certain time. These timestamps cannot be tampered with
later, providing long-term trust. This long-term trust also requires that the
log is monitored.