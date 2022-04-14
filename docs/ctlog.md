# Certificate Transparency Log Information

## Summary

Fulcio maintains a certificate transparency (CT) log, writing all issued certificates to the log.
Users of Sigstore can verify via cryptographic proof that certificates are included in the log
along with monitoring the log for inconsistencies.

The CT log is backed by [Trillian](https://github.com/google/trillian), a highly scalable and
verifiable data store. The `certificate-transparency-go`
[library](https://github.com/google/certificate-transparency-go/tree/master/trillian) implements
[RFC6962](https://datatracker.ietf.org/doc/html/rfc6962), the RFC for certificate transparency.

## Signed Certificate Timestamp (SCT)

[SCTs](https://datatracker.ietf.org/doc/html/rfc6962#section-3) represent a cryptographic promise
that the CT server will include an entry in the log within a fixed amount of time. The SCT contains
a signature over a timestamp and certificate. It is verified using the log's public key, which is
included in Sigstore's TUF metadata.

SCTs can either be embedded in a certificate or detached from the certificate. If an SCT is detached,
this means that Fulcio returns the SCT alongside the certificate, and it's up to the caller to store
the SCT. For example, with Cosign, the SCT is not stored, so it is only verified during artifact
signing. All callers should be storing certificates, so SCTs embedded in the certificate can be
verified both during artifact signing and verification.

For each of Fulcio's signing backends, a backend always implements support for a detached SCT,
and optionally implements support for embedded SCTs.

### Generating an embedded SCT

To generate a certificate with an embedded SCT, two certificates are issued: A precertificate
and a final certificate. The precertificate is an invalid certificate that contains all of the
same valules as the final certificate, except for one extension, the poison extension. The
precertificate is written to the transparency log, and its values are used to generate the SCT.

The purpose of the precertificate is to solely to generate an SCT. If the CA fails to write the
precertificate to the log and no SCT is issued, the CA has not signed a valid certificate, so there
is no issue. If the CA had to sign a valid certificate once to write to the log, and again to embed
the SCT, if there's an error after the first step, a valid certificate would have been issued, and
must then be revoked.

The SCT is signed over a timestamp and certificate body, called the to-be-signed (TBS) certificate.
The TBS certificate is a certificate without a signature. Since the signatures for the precertificate
and certificate will never match, the TBS is used to generate the SCT. When generating the SCT, the
poison extension is also removed from the TBS certificate. Additionally, the SCT is signed over a hash
of the issuing certificate's public key, to bind the issuer to the certificate.

After the log returns an SCT, the CA embeds the SCT in a specific extension, before signing the final
certificate. Note that a certificate can contain a list of SCTs, for each log that contains
the precertificate.

An example SCT from `openssl`:

```
CT Precertificate SCTs:
    Signed Certificate Timestamp:
        Version   : v1 (0x0)
        Log ID    : 7A:42:62:CF:F6:69:1B:E5:04:9F:9C:3F:19:A2:2B:EB:
                    E6:B0:23:E4:4A:7E:4A:6D:FD:5F:53:7A:EE:EF:6B:59
        Timestamp : Apr  2 22:05:57.390 2022 GMT
        Extensions: none
        Signature : ecdsa-with-SHA256
                    30:45:02:21:00:F0:7F:46:BA:48:5C:5C:7D:7B:CF:3A:
                    44:C7:AB:7A:AD:0B:EC:13:18:A9:D1:1F:D6:31:0A:C8:
                    4A:FE:08:A3:8C:02:20:67:33:86:4A:02:F8:B9:21:7D:
                    33:9F:45:F7:77:1D:6B:C1:6F:23:3A:41:91:BB:20:96:
                    5A:AA:FA:09:C3:B5:47
```

`Log ID` is the SHA256 digest of the DER-encoded log public key, which can be used to look up
the SCT verification key.

See the `certificate-transparency-go`
[library](https://github.com/google/certificate-transparency-go) for more details.

[1] The additional extension, the poison extension, is used to make the certificate invalid.
It is an extension with a specific OID, a null value, and is marked as a critical extension.
Verifiers must reject a certificate that has a critical extension whose purpose is not known.
Therefore, either a verifier is not aware of the poison extension's OID, rejecting a
certificate with the critical poison extension, or the verifier is aware of the purpose of the
extension, rejecting the certificate nonetheless.

### Verifying an SCT

To verify an embedded SCT, a verifier must have the final certificate and its issuing certificate.
The SCT is verified using the log's public key, which is distributed out of band. For Cosign, it
is distributed in the TUF metadata.
The client will reconstruct the TBS precertificate by removing the SCT extension and the certificate
signature. With the timestamp of issuance and a digest of the issuer's public key, the verifier
can reconstruct what the SCT was signed over, and verify the SCT's signature.

## Sharding strategy

A CT log can grow indefinitely, only bounded by the size of the underlying database. A large CT log
will take longer for auditors to verify, and will also increase the burden on log replicators. Therefore,
we need to create log shards, where after a certain period, a new log is turned up and the old log is
frozen, accepting no more entries.

We will create new log shards each year. The log's name will be the year. Currently, the log is accessible
at `https://ctfe.sigstore.dev/test`. After sharding the log, the log will be accessible at
`https://ctfe.sigstore.dev/2022`. We can use the same signing key for each year's shard, so that we don't
need to distribute a new key each year in the TUF metadata.
