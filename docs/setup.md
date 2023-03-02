# Setting up a local Fulcio instance

There are two simple ways to set up Fulcio.

The first is to use `docker-compose up`. This sets up both Fulcio and the Trillian instance
used for the certificate transparency (CT) log. See below for details on customizing the signing
backend, as the default uses an ephemeral CA that is not persisted. 

Simply run:

```
docker-compose up
```

The other way is running the Fulcio binary:

```
go run main.go serve --port 5555 --ca ephemeralca --ct-log-url=""
```

This serves the API without a CT log, which is not recommended for production.
See [sigstore-the-local-way](https://github.com/tstromberg/sigstore-the-local-way) to
learn more about setting up Trillian.

## Signing backend

Fulcio supports various modes to generate its code-signing certificates. These modes
support different signing backends that are responsible for both generating and
signing a certificate.

Note that when using `docker-compose`, you may need to mount files under `volumes`.

### KMS

The KMS signing backend uses KMS to generate a certificate signature. This requires
setting up a KMS key with a cloud provider, such as AWS, GCP, Azure or Hashicorp Vault.
You will also need to certify the public key of the signer, providing a certificate
chain. The CA can either run as an intermediate CA chaining up to an offline root CA,
or as a root CA, though the KMS signing backend is primarily meant to be used as an
intermediate CA.

Configuration:
* `--ca=kmsca`
* `--kms-resource=gcpkms://<resource>`, also supporting `awskms://`, `azurekms://` or `hashivault://`
* `--kms-cert-chain-path=/...`, a PEM-encoded certificate chain

Be sure to run `gcloud auth application-default login` before `docker-compose up` so that
your credentials are mounted on the container.

### Tink

The Tink signing backend uses an on-disk signer loaded from an encrypted Tink keyset and
certificate chain, where the first certificate in the chain certifies the public key from
the Tink keyset. The Tink keyset must be encrypted with a GCP KMS key, and stored in
a JSON format. The CA can either run as an intermediate CA chaining up to an offline root CA,
or as a root CA.

**Tink keysets use strong security defaults and are the most secure way to store an encryption
key locally.**

The supported Tink keysets are:
* ECDSA P-256, SHA256 hash
* ECDSA P-384, SHA512 hash
* ECDSA P-521, SHA512 hash
* ED25519

Configuration:
* `--ca=tinkca`
* `--tink-kms-resource=gcp-kms://<resource>`, also supporting `aws-kms://`
* `--tink-keyset-path=/...`, a JSON-encoded encrypted Tink keyset
* `--tink-cert-chain-path=/...`, a PEM-encoded certificate chain

Be sure to run `gcloud auth application-default login` before `docker-compose up` so that
your credentials are mounted on the container.

### Google Cloud Platform CA Service

The GCP CA Service signing backend delegates creation and signing of the certificates
to a CA managed in GCP. You will need to create a DevOps-tier CA pool and one CA in the
CA pool. This can either be an intermediate or root CA.

We currently do not support the following CA Service configurations. Please file an
issue if you need support.
* Enterprise-tier CA pools (The certificate ID is not sent in the request)
* CA pools with multiple CAs (Multiple places in the code expect only one certificate chain)

Configuration:
* `--ca=googleca`
* `--gcp_private_ca_parent=projects/<project>/locations/<location>/caPools/<CA-pool>`

Be sure to run `gcloud auth application-default login` before `docker-compose up` so that
your credentials are mounted on the container.

### On-disk file

The on-disk file-based signing backend loads an encrypted key and certificate chain, and also
monitors for changes to either, reloading the key and chain without requiring a server reboot.
This signer supports a CA as either a root or intermediate.

See [generate.sh](https://github.com/sigstore/fulcio/blob/f024a03d981f9f955b259ee7c126dd5c08d534b3/pkg/ca/fileca/testdata/generate.sh)
for examples of how to generate an encrypted private key using OpenSSL.

Configuration:
* `--ca=fileca`
* `--fileca-cert=/...`, a PEM-encoded certificate chain
* `--fileca-key`, a PEM-encoded encrypted signing key (RSA, ECDSA, and ED25519 are supported) 
* `--fileca-key-passwd`, the password to decrypt the signing key

### PKCS11 HSM

The PKCS11 signing backend supports using an HSM to sign certificates.

Configuration:
* `--ca=pkcs11ca`
* `--pkcs11-config-path=/...`, a path to a PKCS11 configuration. See `config/crypto11.conf` 
* `--hsm-caroot-id=...`
* Optional: `--aws-hsm-root-ca-path=...`, a path to an AWS HSM resource

See [HSM Support](hsm-support.md) for more information.

### Ephemeral - **For testing only**

Ephemeral CAs create the key material in memory and destroy the key material on server
turndown. **Do not use ephemeral CAs for production.**

Configuration:
* `--ca=ephemeralca`

To view the root certificate, you can access it at
`http://localhost:5555/api/v1/rootCert`:

```
curl http://localhost:5555/api/v1/rootCert

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

## Certificate Transparency Log support

All signing backends can be configured to write issued certificates to a transparency log.
Signed certificate timestamps (SCTs), proof of inclusion in the log, are returned in a
custom HTTP header or gRPC field.

Only the KMS and File-based signing backends support embedded SCTs currently. Embedded
SCTs are recommended, since a client can easily verify proof of inclusion when using
the certificate for artifact verification, without needing to store the detached SCT
alongside the certificate.

See [CT Log](ctlog.md) for more information.

## CA Certificate requirements

Certain signing backends, such as the KMS and file-based backends, require providing
your own CA certificate chain. An example PEM-encoded certificate chain:

```
-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----
```

Save the chain to `chain.crt` and parse with
`openssl crl2pkcs7 -nocrl -certfile chain.crt | openssl pkcs7 -print_certs -text -noout`.

For the root certificate:
* Subject with a common name and organization
* Key usages: Certificate Sign, CRL Sign
* CA basic constraints: CA:TRUE
    * You can optionally limit the root with a path length to prevent additional
      CA certificates from being issued beneath that root.
* Subject public key: We recommend using ECDSA-P384 (secp384r1) or higher, or RSA-4096.

For the intermediate certificate:
* Subject with a common name and organization
* Key usages: Certificate Sign, CRL Sign
* Extended key usage: Code Signing
* Lifetime does not exceed the parent certificate
* CA basic constraints: CA:TRUE, pathlen:0
    * You can choose to add a different path length constraint, but we recommend limiting
      the intermediate CA to only issue leaf certificates.
* Subject public key: We recommend using ECDSA-P384 (secp384r1) or higher, or RSA-4096.
  We don't recommend mixing signing algorithms within the chain.

## Calling the Fulcio API

To call Fulcio, you can either use `curl` or the gRPC client. It's easiest to use
Cosign to call the local instance of Fulcio. You can configure Cosign to call
the local instance with `--fulcio-url`, for example:

```
cosign sign --yes --fulcio-url http://localhost:5555 container
```

You will also need to configure Cosign with the local instance's root
certificate and CT log public key. You can do so by setting up a local
TUF repository, following
[this guide](https://blog.sigstore.dev/sigstore-bring-your-own-stuf-with-tuf-40febfd2badd)

Alternatively, **for non-production testing only**, you can use environment
variables to configure the root certificate and public key.

Set `SIGSTORE_ROOT_FILE` with the path to a PEM-encoded root certificate.
To get the root certificate, call `curl -o fulcio.crt.pem http://localhost:5555/api/v1/rootCert`.

Set `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` with the path to a PEM or DER-encoded CT log public key.
If using `docker-compose`, the public key is available at `config/ctfe/pubkey.pem`.
