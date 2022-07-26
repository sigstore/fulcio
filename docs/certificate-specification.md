# Certificate Specification

This document includes the requirements for root, intermediate, and issued certificates.
This document applies to all instances of Fulcio, including the production instance and
all private instances using the service defined in this repository.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are
to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

## Root Certificate

A root certificate MUST:

* Specify a Subject with a common name and organization
* Specify an Issuer with the same values as the Subject
* Specify Key Usages for Certificate Sign and CRL Sign
* Specify Basic Constraints to `CA:TRUE`
* Specify a unique, positive, 160 bit serial number
* Specify a Subject Key Identifier
* Be compliant with [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)

A root certificate MUST NOT:

* Specify other Key Usages besides Certificate Sign and CRL Sign
* Specify any Extended Key Usages

A root certificate SHOULD:

* Use the signing algorithm ECDSA NIST P-384 (secp384r1) or stronger, or RSA-4096
* Have a lifetime that does not require frequent rotation, such as 10 years

A root certificate MAY:

* Specify a Basic Constraints path length constraint to prevent additional CA certificates
  from being issued beneath the root
* Specify an Authority Key Identifier. If specified, it MUST be the same as the Subject Key Identifier
* Specify other values in the Subject

## Intermediate Certificate

An intermediate certificate MUST:

* Specify a Subject with a common name and organization
* Specify an Issuer equal to the parent certificate's Subject
* Specify Key Usages for Certificate Sign and CRL Sign
* Specify an Extended Key Usage for Code Signing
* Specify a lifetime that does not exceed the parent certificiate
* Specify Basic Constraints to `CA:TRUE`
* Specify a unique, positive, 160 bit serial number
* Specify a Subject Key Identifier
* Specify an Authority Key Identifier equal to the parent certificate's Subject Key Identifier 
* Be compliant with [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)

An intermediate certificate MUST NOT:

* Specify other Key Usages besides Certificate Sign and CRL Sign
* Specify other Extended Key Usages besides Code Signing

An intermediate certificate SHOULD:

* Specify a Basic Constraints path length constraint of 0, `pathlen:0`. This limits the intermediate
  CA to only issue end-entity certificates
* Use the signing algorithm ECDSA NIST P-384 (secp384r1) or stronger, or RSA-4096
* Have a lifetime that does not require frequent rotation, such as 3 years

An intermediate certificate SHOULD NOT:

* Use a different signature scheme (ECDSA vs RSA) than its parent certificate, as some clients do not support this

An intermediate certificate MAY:

* Be optional. An end-entity certificate MAY be issued from a root certificate or an intermediate certificate.
  Clients MUST be able to verify a chain with any number of intermediate certificates.

## Issued Certificate

An issued certificate MUST:

* Specify exactly one Subject Alternative Name, as a critical extension. It MUST be populated by either:
   * An email
   * A URI
* Specify an Issuer equal to the parent certificate's Subject
* Specify a Key Usage for Digital Signature 
* Specify an Extended Key Usage for Code Signing
* Specify a lifetime that does not exceed the parent certificiate
* Specify a unique, positive, 160 bit serial number
* Specify a Subject Key Identifier
* Specify an Authority Key Identifier equal to the parent certificate's Subject Key Identifier 
* Specify an empty Subject
* Be compliant with [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)
* Specify a public key that is either:
   * ECDSA NIST P-256, NIST P-384, or NIST P-521
   * RSA of key size 2048 to 4096 (inclusive) with size % 8 = 0, E = 65537, and containing no weak primes
   * ED25519
* Specify the OpenID Connect identity token issuer with OID `1.3.6.1.4.1.57264.1.1`
* Be appended to a Certificate Transparency log. Clients MUST NOT trust certificates that do not present
  either a proof of inclusion or a Signed Certificate Timestamp (SCT)

An issued certificate MUST NOT:

* Specify a nonempty Subject
* Specify multiple Subject Alternative Name values
* Specify other Key Usages besides Digital Signature
* Specify other Extended Key Usages besides Code Signing

An issued certificate SHOULD:

* Use an ephemeral key. A client MAY request a certificate with a long-lived key, but a client MUST
  adequately secure the key material
* Append a precertificate to a Certificate Transparency log, where the precertificate MUST be signed by the certificate authority
  and MUST include a poison extension with OID `1.3.6.1.4.1.11129.2.4.3`
* Specify the Signed Certificate Timestamp (SCT) from the Certificate Transparency log with OID `1.3.6.1.4.1.11129.2.4.2`

An issued certificate SHOULD NOT:

* Use a different public key scheme (ECDSA vs RSA) than its parent certificate, as some clients do not support this
* Specify a public key that is stronger than its parent certificate

An issued certificate MAY:

* Specify Basic Constraints to `CA:FALSE`
* Specify values from the OpenID Connect identity token in OIDs prefixed with `1.3.6.1.4.1.57264.1`,
  such as values from a GitHub Actions workflow
* Specify multiple SCTs with OID `1.3.6.1.4.1.11129.2.4.2`, denoting that the certificate has been appended to multiple logs
* Specify the Signed Certificate Timestamp (SCT) in a response header `SCT` instead of embedding the SCT in the certificate