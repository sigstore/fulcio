# Security Model

Fulcio assumes that a valid OIDC token is a sufficient "proof of ownership" of
an email address.

To mitigate against this, Fulcio uses a Transparency log to help protect
against OIDC compromise. This means:

- Fulcio MUST publish all certificates to the log.
- Clients MUST NOT trust certificates that are not in the log.

As a result users can detect any mis-issued certificates.

Combined with `rekor's` signature transparency, artifacts signed with
compromised accounts can be identified.

## Revocation, Rotation and Expiry

There are two main approaches to code signing:

1. Long-term certs
2. Trusted time-stamping

### Long-term certs

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

This can be done a few ways:

* Third-party Timestamp Authorities (RFC3161)
* Transparency Logs
* Both (Fulcio's Model)

### RFC3161 Timestamp Servers

RFC3161 defines a protocol for Trusted Timestamps.  Parties can send a payload
to an RFC3161 service and the service digitally signs that payload with its own
timestamp.  This is the equivalent of posting a hash to Twitter - you are
getting a third-party attestation that you had a particular piece of data at a
particular time, as observed by that same third-party.

The downside is that users need to interact with another service.  They must
timestamp all signatures and check the timestamps of all signatures - adding
another dependency and set of keys they must trust (the timestamp servers).  We
could provide one for free, but if people don't trust the clock in our
transparency ledger they might not trust another service we run.

### Transparency Logs

The `rekor` service provides a [transparency log][transparency-ref] of software
signatures.  As entries are appended into this log, `rekor` periodically signs
the full tree along with a timestamp.

[transparency-ref]: https://transparency.dev/verifiable-data-structures/

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

### Why Not Both!?!?!?

Like usual, we can combine timestamp servers and transparency logs to do a bit
better.

Third-party timestamp authorities provide signatures for pieces of data, which
includes a timestamp.  Rekor can interact with these third-party TSAs
automatically, allowing users to skip this step.  Rekor can get its own STH
(including the timestamp) signed by one or many third-party TSAs regularly.

Each timestamp attestation in the Rekor log provides a fixed "fencepost" in
time.  Rekor, the client and a third-party can all provide evidence of the
state of the world at a point in time.  Fenceposts every ten minutes protect
all data in between.  Auditors can monitor Rekor's log to ensure these are
added, shifting the complexity burden from users to auditors.
