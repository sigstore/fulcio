# Security Model

Fulcio assumes that a valid OIDC token is a sufficient "proof of ownership" of
an email address.

To mitigate against this, Fulcio uses a transparency log to help protect
against OIDC compromise. This means:

- Fulcio MUST publish all certificates to the log.
- Clients MUST NOT trust certificates that are not in the log.

As a result users can detect any mis-issued certificates.

Combined with `rekor's` signature transparency, artifacts signed with
compromised accounts can be identified.

## Revocation, Rotation and Expiry

### Long-term Certificates

These certificates are typically valid for years.  All old code must be
re-signed with a new cert before an old cert expires.  Typically this works
with long deprecation periods, dual-signing and planned rotations.

There are a couple problems with this approach:

1. It assumes users can keep acess to private keys and keep them secret over
   long periods of time
2. Revocation is hard and doesn't work well

### Fulcio's Model

Fulcio is designed to avoid revocation, by issuing *short-lived certificates*.
What really matters for code signing is to know that an artifact was signed
while the certificate was valid.

Sigstore accomplishes this with a tranpsarency log called
[Rekor](https://github.com/sigstore/rekor). A verifier should check that the
inclusion time in the log was during the certificate's validity period.

An entry in Rekor provides a single-party attestation that a piece of data
existed prior to a certain time.  These timestamps cannot be tampered with
later, providing long-term trust.  This long-term trust also requires that the
log is monitored.

Transparency Logs make it hard to forge timestamps long-term, but in short
time-windows it would be much easier for the Rekor operator to fake or forge
timestamps.  To mitigate this, Rekor's timestamps and tree head are signed - a
valid Signed Tree Head (STH) contains a non-repudiadable timestamp.  These
signed timestamp tokens are saved as evidence in case Rekor's clock changes in
the future. So, more skeptical parties don't have to trust Rekor at all!