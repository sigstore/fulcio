[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/fulcio)

<p align="center">
  <img style="max-width: 100%;width: 300px;margin-top: 20px;" src="./docs/img/logo.svg" alt="Fulcio logo"/>
</p>

# Fulcio

_A New Kind of Root CA For Code Signing_

fulcio is a free Root-CA for code signing certs - issuing certificates based on an OIDC email address.

fulcio only signs short-lived certificates that are valid for under 20 minutes.

## Status

Fulcio is a *work in progress*!

We're currently working hard on cutting a 1.0 release and productionizing the public instance.
We don't have a date yet, but follow along on the [GitHub project](https://github.com/orgs/sigstore/projects/5).

The fulcio root certificate running on our public instance (https://fulcio.sigstore.dev) can be obtained and verified against Sigstore's root (at the [sigstore/root-signing](https://github.com/sigstore/root-signing) repository). To do this, install and use [go-tuf](https://github.com/theupdateframework/go-tuf)'s CLI tools:
```
$ go get github.com/theupdateframework/go-tuf/cmd/tuf
$ go get github.com/theupdateframework/go-tuf/cmd/tuf-client
```

Then, obtain trusted root keys for Sigstore. This can be done from a checkout of the Sigstore's root signing repository at a trusted commit (e.g. after the livestreamed root signing ceremony).
```
$ git clone https://github.com/sigstore/root-signing
$ cd root-signing && git checkout 193343461a4d365ac517b5d668e01fbaddd4eba5
$ tuf -d ceremony/2021-06-18/ root-keys > sigstore-root.json
```

Initialize the TUF client with the previously obtained root keys and get the current Fulcio root certificate `fulcio_v1.crt.pem`.
```
$ tuf-client init https://raw.githubusercontent.com/sigstore/root-signing/main/repository/repository/ sigstore-root.json
$ tuf-client get https://raw.githubusercontent.com/sigstore/root-signing/main/repository/repository/ fulcio_v1.crt.pem 
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

We **WILL** change this and add intermediaries in the future.

## API

The API is defined [here](./pkg/api/client.go).

## Transparency

Fulcio will publish issued certificates to a unique Certificate Transparency log (CT-log).
That log will be hosted by the sigstore project.

We encourage auditors to monitor this log, and aim to help people access the data.

A simple example would be a service that emails users (on a different address) when certficates have been issued on their behalf.
This can then be used to detect bad behavior or possible compromise.


## Security

Should you discover any security issues, please refer to sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

## Info

`Fulcio` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
