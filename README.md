# fulcio - A New Kind of Root CA For Code Signing

fulcio is a free Root-CA for code signing certs - issuing certificates based on an OIDC email address.

fulcio only signs short-lived certificates that are valid for under 20 minutes.

## Status

Fulcio is a *work in progress*.
There's working code and a running instance and a plan, but you should not attempt to try to actually use it for anything.

The fulcio root cert running on our public instance (https://fulcio.sigstore.dev) is currently:

```
-----BEGIN CERTIFICATE-----
  MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAq
  MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
  MDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUu
  ZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSy
  A7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0Jcas
  taRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6Nm
  MGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
  FMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2u
  Su1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJx
  Ve/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uup
  Hr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==
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

The API is defined via OpenAPI, defined [here](openapi.yaml).

## Transparency

Fulcio will publish issued certificates to a unique Certificate Transparency log (CT-log).
That log will be hosted by the sigstore project.

We encourage auditors to monitor this log, and aim to help people access the data.

A simple example would be a service that emails users (on a different address) when ceritficates have been issued on their behalf.
This can then be used to detect bad behavior or possible compromise.

## CA / KMS support

### Google Cloud Platform Private CA

The public fulcio root CA is currently running on GCP Private CA with the EC_P384_SHA384 algorithm.

You can also run with your own GCP Private CA, by passing in a parent and google as the CA

```
go run main.go serve --ca googleca  --gcp_private_ca_parent=projects/myproject/locations/us-central1/certificateAuthorities/myproject
```

### PKCS11CA


fulcio may also be used with a pkcs11 capable device such as a SoftHSM. You will also need `pkcs11-tool`

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

## Security Model

* Fulcio assumes that a valid OIDC token is a sufficient "proof of ownership" of an email address.

* To mitigate against this, Fulcio uses a Transparency log to help protect against OIDC compromise. This means:
    * Fulcio MUST publish all certificates to the log.
    * Clients MUST NOT trust certificates that are not in the log.

  As a result users can detect any mis-issued certificates.

* Combined with `rekor's` signature transparency, artifacts signed with compromised accounts can
  be identified.

### Revocation, Rotation and Expiry

There are two main approaches to code signing:
1. Long-term certs
1. Trusted time-stamping

#### Long-term certs

These certificates are typically valid for years.
All old code must be re-signed with a new cert before an old cert expires.
Typically this works with long deprecation periods, dual-signing and planned rotations.

There are a couple problems with this approach:
1. It assumes users can keep acess to private keys and keep them secret over
log periods of time
1. Revocation is hard and doesn't work well

#### Fulcio's Model

Fulcio is designed to avoid revocation, by issuing *short-lived certificates*.
What really matters for CodeSigning is to know that an artifact was signed while the
certificate was valid.

This can be done a few ways:

* Third-party Timestamp Authorities (RFC3161)
* Transparency Logs
* Both (Fulcio's Model)

#### RFC3161 Timestamp Servers

RFC3161 defines a protocol for Trusted Timestamps.
Parties can send a payload to an RFC3161 service and the service digitally signs that payload with
its own timestamp.
This is the equivalent of posting a hash to Twitter - you are getting a third-party attestation that
you had a particular piece of data at a particular time, as observed by that same third-party.

The downside is that users need to interact with another service.
They must timestamp all signatures and check the timestamps of all signatures - adding
another dependency and set of keys they must trust (the timestamp servers).
We could provide one for free, but if people don't trust the clock in our transparency ledger they might
not trust another service we run.

#### Transparency Logs

The `rekor` service provides a [transparency log](https://transparency.dev/verifiable-data-structures/) of software signatures.
As entries are appended into this log, `rekor` periodically signs the full tree along with a timestamp.

An entry in Rekor provides a single-party attestation that a piece of data existed prior to a certain time.
These timestamps cannot be tampered with later, providing long-term trust.
This long-term trust also requires that the log is monitored.

Transparency Logs make it hard to forge timestamps long-term, but in short time-windows it would be much easier for
the Rekor operator to fake or forge timestamps.
To mitigate this, Rekor's timestamps and tree head are signed - a valid Signed Tree Head (STH) contains a non-repudiadable timestamp.
These signed timestamp tokens are saved as evidence in case Rekor's clock changes in the future.
So, more skeptical parties don't have to trust Rekor at all!

#### Why Not Both!?!?!?

Like usual, we can combine timestamp servers and transparency logs to do a bit better.

Third-party timestamp authorities provide signatures for pieces of data, which includes a timestamp.
Rekor can interact with these third-party TSAs automatically, allowing users to skip this step.
Rekor can get its own STH (including the timestamp) signed by one or many third-party TSAs regularly.

Each timestamp attestation in the Rekor log provides a fixed "fencepost" in time.
Rekor, the client and a third-party can all provide evidence of the state of the world at a point in time.
Fenceposts every ten minutes protect all data in between.
Auditors can monitor Rekor's log to ensure these are added, shifting the complexity burden from users to auditors.

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

## Info

`Fulcio` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
