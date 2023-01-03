## HSM Support 

### PKCS11CA

Fulcio may also be used with a pkcs11 capable device such as a SoftHSM. You will also need `pkcs11-tool`.

You will need to specify `CGO_ENABLED=1`, since PKCS11 support requires C libraries.

> :warning: A SoftHSM does not provide the same security guarantees as a hardware-based HSM.
> **Use for testing only.**

You will need `pkcs11-tool`. On Debian, you can install the necessary tools with:

```
apt-get install softhsm2 opensc
```

To configure a SoftHSM:

Create a `config/crypto11.conf` file:

```json
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

Make sure `/tmp/tokens` exists

```shell
mkdir /tmp/tokens
```

Export the `config/softhsm2.conf`

```
export SOFTHSM2_CONF=`pwd`/config/softhsm2.conf
```

### Start a SoftHSM instance

```shell
# Note: these pins match config/crypto11.conf above
softhsm2-util --init-token --slot 0 --label fulcio --pin 2324 --so-pin 2324
```

### Create keys within the SoftHSM

```shell
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so --login --login-type user --keypairgen --id 1 --label PKCS11CA  --key-type EC:secp384r1
```

* Note: you can import existing keys and import using pkcs11-tool, see pkcs11-tool manual for details

### Create a root CA

Now that your keys are generated, you can use the fulcio `createca` command to generate a Root CA. This command
will also store the generated Root CA into the HSM by the delegated id passed to `--hsm-caroot-id`

```shell
fulcio createca --org=acme --country=UK --locality=SomeTown --province=SomeProvince --postal-code=XXXX --street-address=XXXX --hsm-caroot-id 99 --out myrootCA.pem
```

`fulcio createca` will return a root certificate if used with the `-o` flag.

### Run PKCS11CA

```
fulcio serve --ca pkcs11ca --hsm-caroot-id 99
```

> :warning: A SoftHSM does not provide the same security guarantees as a hardware-based HSM.
> **Use for testing only.**

---
**NOTE**

PKCS11CA has only been validated against a SoftHSM. In theory this should also work with all PCKS11 compliant
HSM's, but to date we have only tested against a SoftHSM.

---
