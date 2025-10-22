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

## Claims-based Authorization

Fulcio supports optional claims-based authorization that provides an additional security layer
beyond OIDC authentication. This enables fine-grained access control policies based on
authenticated token claims.

### Defense in depth

The security model operates in layers:

1. **Authentication**: Verifies OIDC token is valid and from trusted issuer
2. **Authorization** (Optional): Verifies authenticated identity should have access

### Authorization security benefits

- **Principle of least privilege**: Restrict access to only required identities
- **Policy enforcement**: Implement organizational security policies
- **Audit trail**: Detailed logging of authorization decisions

### Example of security scenarios

**Without authorization**:
- Any valid GitHub token can request certificates
- Compromised repository has broad certificate access
- Difficult to implement organizational policies

**With authorization**:
- Only specified repositories can request certificates
- Compromise is limited to explicitly allowed resources
- Clear policy enforcement and violation detection

### Configuration security

Fulcio prioritizes security over availability in authorization configuration and follows these principles:

- **Early validation**: All rules and regex patterns are validated at startup
- **Fail-secure by design**: Invalid authorization rules prevent server startup (malformed rules never fall back to allow-all behavior)
- **Regular expressions are compiled once at startup** (no ReDoS risk)
- **Rules are evaluated against authenticated claims only**
- **Authorization cannot be bypassed through token manipulation**
- **All decisions are logged for audit and monitoring**

This approach ensures that authorization policies are always correctly applied and prevents security misconfigurations from going unnoticed.

See [Authorization documentation](authorization.md) for detailed configuration.

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