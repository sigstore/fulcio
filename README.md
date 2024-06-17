[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio)

<p align="center">
  <img style="max-width: 100%;width: 300px;margin-top: 20px;" src="https://raw.githubusercontent.com/sigstore/community/main/artwork/fulcio/horizontal/color/sigstore_fulcio-horizontal-color.svg" alt="Fulcio logo"/>
</p>

# Fulcio

_A Free-to-Use CA For Code Signing_

Fulcio is a free-to-use certificate authority for issuing code signing certificates
for an OpenID Connect (OIDC) identity, such as email address.

Fulcio only issues short-lived certificates that are valid for 10 minutes.

## Public Instance

Fulcio is in General Availability, offering a 99.5 Availability SLO,
and follows [semver rules](https://semver.org/) for API stability.

For uptime data on the Fulcio public instance, see [https://status.sigstore.dev](https://status.sigstore.dev).

Fulcio's certificate chain can be obtained from the `TrustBundle` API, for example for the public instance
([https://fulcio.sigstore.dev](https://fulcio.sigstore.dev/api/v2/trustBundle)). To verify the public instance,
you must verify the chain using Sigstore's [TUF](https://theupdateframework.io/) root from the
[sigstore/root-signing](https://github.com/sigstore/root-signing) repository).

To do this, install and use [go-tuf](https://github.com/theupdateframework/go-tuf)'s CLI tools:

```
$ go install github.com/theupdateframework/go-tuf/cmd/tuf-client@latest
```

Then, obtain trusted root keys for Sigstore. You will use the 5th iteration of Sigstore's TUF root to start the root of trust, due to
a backwards incompatible change.

```
curl -o sigstore-root.json https://raw.githubusercontent.com/sigstore/root-signing/main/ceremony/2022-10-18/repository/5.root.json
```

Initialize the TUF client with the previously obtained root and the remote repository, https://tuf-repo-cdn.sigstore.dev,
and get the current Fulcio root certificate `fulcio_v1.crt.pem` and intermediate certificate `fulcio_intermediate_v1.crt.pem`.
```
$ tuf-client init https://tuf-repo-cdn.sigstore.dev sigstore-root.json

$ tuf-client get https://tuf-repo-cdn.sigstore.dev fulcio_v1.crt.pem
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

$ tuf-client get https://tuf-repo-cdn.sigstore.dev fulcio_intermediate_v1.crt.pem
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
```

### Verifying releases

You can also verify signed releases (`fulcio-<os>.sig`) using the artifact signing key:

```
tuf-client get https://tuf-repo-cdn.sigstore.dev artifact.pub > artifact.pub

curl -o fulcio-release.sig -L https://github.com/sigstore/fulcio/releases/download/<version>/fulcio-<os>.sig
base64 -d fulcio-release.sig > fulcio-release.sig.decoded

curl -o fulcio-release -L https://github.com/sigstore/fulcio/releases/download/<version>/fulcio-<os>

openssl dgst -sha256 -verify artifact.pub -signature fulcio-release.sig.decoded fulcio-release
```


## API

The API is defined [here](./fulcio.proto). The API can be accessed
over [HTTP](https://www.sigstore.dev/swagger/?urls.primaryName=Fulcio) or gRPC.

## Certificate Transparency

Fulcio will publish issued certificates to a Certificate Transparency log (CT log).
The log is hosted at `https://ctfe.sigstore.dev/test`. Each year, the log will be updated
to a new log ID, for example `https://ctfe.sigstore.dev/2022`.

The log provides an API documented in [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/).

We encourage auditors to monitor this log for both integrity and specific identities.
For example, auditors can monitor for when a certificate is issued for certain email addresses,
which will detect misconfiguration or potential compromise of the user's identity.

## Security

Please report any vulnerabilities following sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

## Info

Fulcio is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
To check more information about Slack and other communication channels please check the [community repository](https://github.com/sigstore/community?tab=readme-ov-file#slack)

## Additional Documentation

In addition to this README file, the docs folder contains the additional documentation:

- **certificate-specification.md**. This file includes the requirements for root, intermediate, and issued certificates.   The document applies to all instances of Fulcio, including the production instance and all private instances.
- **ctlog.md**. Certificate transparency log information, including information on signed certificate timestamps and a sharding strategy for the  CT log.
- **how-certifcate-issuing-works.md**. This document walks through the process of issuing a code signing certificate.  
- **hsm-support.md**. Using Fulcio with a pkcs11 capable device such as SoftHSM.
- **oid-info.md**. Sigstore OID information.  
- **security-model.md**. Fulcio’s security model and a discussion of short-lived certificates.
- **setup.md**. Setting up a local Fulcio instance

If you are making changes to any of these subjects, make sure you also edit the appropriate file listed above.

