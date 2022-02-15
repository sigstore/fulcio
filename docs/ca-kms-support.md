## CA / KMS support

### Google Cloud Platform CA Service

The public Fulcio root CA is currently running on [GCP CA Service](https://cloud.google.com/certificate-authority-service/docs) with the EC_P384_SHA384 algorithm.

You can also run Fulcio with your own CA on CA Service by passing in a parent and specifying Google as the CA:

```
go run main.go serve --ca googleca  --gcp_private_ca_parent=projects/myproject/locations/us-central1/caPools/mypool
```

### PKCS11CA

Fulcio may also be used with a pkcs11 capable device such as a SoftHSM. You will also need `pkcs11-tool`.

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
