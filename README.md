# fulcio - A New Kind of Root CA For Code Signing

fulcio is a free Root-CA for code signing certs - issuing certificates based on an OIDC email address.

fulcio only signs short-lived certificates that are valid for under 20 minutes.

## Status

Fulcio is a *work in progress*.
There's working code and a running instance and a plan, but you should not attempt to try to actually use it for anything.

The fulcio root certificate running on our public instance (https://fulcio.sigstore.dev) can be obtained and verified against Sigstore's root (at the [sigstore/root-signing](https://github.com/sigstore/root-signing) repository). To do this, install and use [go-tuf](https://github.com/theupdateframework/go-tuf)'s CLI tools:
```
$ go get github.com/theupdateframework/go-tuf/cmd/tuf
$ go get github.com/theupdateframework/go-tuf/cmd/tuf-client
```

Then, obtain trusted root keys for Sigstore. This can be done from a checkout of the Sigstore's root signing repository at a trusted commit (e.g. after the livestreamed root signing ceremony)
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

## Build for development

After cloning the repository:

```
$ make
```

There are other targets available in the [`Makefile`](Makefile), check it out.

## API

The API is defined [here](./pkg/api/client.go).

## Transparency

Fulcio will publish issued certificates to a unique Certificate Transparency log (CT-log).
That log will be hosted by the sigstore project.

We encourage auditors to monitor this log, and aim to help people access the data.

A simple example would be a service that emails users (on a different address) when ceritficates have been issued on their behalf.
This can then be used to detect bad behavior or possible compromise.

## CA / KMS support

### Google Cloud Platform CA Service

The public Fulcio root CA is currently running on [GCP CA Service](https://cloud.google.com/certificate-authority-service/docs) with the EC_P384_SHA384 algorithm.

You can also run Fulcio with your own CA on CA Service by passing in a parent and specifying Google as the CA:

```
go run main.go serve --ca googleca  --gcp_private_ca_parent=projects/myproject/locations/us-central1/caPools/mypool
```

### PKCS11CA

Fulcio may also be used with a pkcs11 capable device such as a SoftHSM. You will also need `pkcs11-tool`

To configure a SoftHSM:

Create a `config/crypto11.conf` file:

```
{
"Path" : "/usr/lib64/softhsm/libsofthsm.so",
"TokenLabel": "fulcio",
"Pin" : "2324"
}
```

And a `config/softhsm2.conf`

```
directories.tokendir = /tmp/tokens
objectstore.backend = file
log.level = INFO
```

Export the `config/softhsm2.conf`

```
export SOFTHSM2_CONF=`pwd`/config/softhsm2.cfg
```

### Start a SoftHSM instance

```
softhsm2-util --init-token --slot 0 --label fulcio
```

### Create keys within the SoftHSM

```
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so --login --login-type user --keypairgen --id 1 --label PKCS11CA  --key-type EC:secp384r1
```

* Note: you can import existing keys and import using pkcs11-tool, see pkcs11-tool manual for details

### Create a root CA

Now that your keys are generated, you can use the fulcio `createca` command to generate a Root CA. This command
will also store the generated Root CA into the HSM by the delegated id passed to `--hsm-caroot-id`

```
fulcio createca --org=acme --country=UK --locality=SomeTown --province=SomeProvince --postal-code=XXXX --street-address=XXXX --hsm-caroot-id 99 --out myrootCA.pem
```

### Run PKCS11CA

```
fulcio serve --ca pkcs11ca --hsm-caroot-id 99
```

> :warning: A SoftHSM does not provide the same security guarantees as hardware based HSM
> Use for test development purposes only.

---
**NOTE**

PKCS11CA has only been validated against a SoftHSM. In theory this should also work with all PCKS11 compliant
HSM's, but to date we have only tested against a SoftHSM.

---


### Other KMS / CA support

Support will be extended to the following CA / KMS systems, feel free to contribute to expedite support coverage

Planned support for:
- [ ] AWS CloudHSM
- [ ] Azure Dedicated HSM
- [ ] YubiHSM

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md)

## Info

`Fulcio` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
