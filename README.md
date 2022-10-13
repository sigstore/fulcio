[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio)

<p align="center">
  <img style="max-width: 100%;width: 300px;margin-top: 20px;" src="./docs/img/logo.svg" alt="Fulcio logo"/>
</p>

# Fulcio

_A Free-to-Use CA For Code Signing_

Fulcio is a free-to-use certificate authority for issuing code signing certificates
for an OpenID Connect (OIDC) identity, such as email address.

Fulcio only issues short-lived certificates that are valid for 10 minutes.

## Status

Fulcio is in General Availability, offering a 99.5 Availability SLO.

For uptime data on the Fulcio public instance, see [https://status.sigstore.dev](https://status.sigstore.dev).

Fulcio's certificate chain can be obtained from the `TrustBundle` API, for example for the public instance
([https://fulcio.sigstore.dev](https://fulcio.sigstore.dev/api/v2/trustBundle)). To verify the public instance,
you must verify the chain using Sigstore's [TUF](https://theupdateframework.io/) root from the
[sigstore/root-signing](https://github.com/sigstore/root-signing) repository).

To do this, install and use [go-tuf](https://github.com/theupdateframework/go-tuf)'s CLI tools:
```
$ go install github.com/theupdateframework/go-tuf/cmd/tuf-client@06ed59941769f55b7d54158a0be85a16a7475fa7
```

Then, obtain trusted root keys for Sigstore. This can be done from a trusted commit in Sigstore's root signing repository
(e.g. after the [livestreamed root signing ceremony](https://github.com/sigstore/root-signing#initial-root-signing-ceremony)).
```
# Ref 193343461a4d365ac517b5d668e01fbaddd4eba5 is when the root ceremony was completed
curl -o sigstore-root.json https://raw.githubusercontent.com/sigstore/root-signing/193343461a4d365ac517b5d668e01fbaddd4eba5/ceremony/2021-06-18/repository/root.json
```

Initialize the TUF client with the previously obtained root and the remote repository, https://sigstore-tuf-root.storage.googleapis.com,
and get the current Fulcio root certificate `fulcio_v1.crt.pem` and intermediate certificate `fulcio_intermediate_v1.crt.pem`.
```
$ tuf-client init https://sigstore-tuf-root.storage.googleapis.com sigstore-root.json

$ tuf-client get https://sigstore-tuf-root.storage.googleapis.com fulcio_v1.crt.pem
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

$ tuf-client get https://sigstore-tuf-root.storage.googleapis.com fulcio_intermediate_v1.crt.pem
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

## API

The API is defined [here](./fulcio.proto). The API can be accessed
over HTTP or gRPC.

## Certificate Transparency

Fulcio will publish issued certificates to a Certificate Transparency log (CT log).
The log is hosted at `https://ctfe.sigstore.dev/test`. Each year, the log will be updated
to a new log ID, for example `https://ctfe.sigstore.dev/2022`.

The log provides an API documented in [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/).

We encourage auditors to monitor this log for both integrity and specific identities.
For example, auditors can monitor for when a certificate is issued for certain eamil addresses,
which will detect misconfiguration or potential compromise of the user's identity.

## Security

Please report any vulnerabilities following sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

## Info

`Fulcio` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
