# Developing Fulcio

Fulcio uses Go and can be run with no other dependencies, other than a trust root PKIX / CA capable system.  Currently
fulcio supports Google certificate authority service (GCP SA) or a PKCS11 capable HSM (such as SoftHSM). PKCS11 support requires C libraries which can cause some issues in
some cases (like building on Mac M1), and if you do not require it, you can
disable support for it by specifying `CGO_ENABLED=0` when building. **NOTE**
This removes the support for `createca` command from the resulting binary.

## GCP SA configuration

You can run locally (outside a container) with GCP SA:

```
go run main.go serve --port 5555 --ca googleca --gcp_private_ca_parent=projects/<project>/locations/<location>/certificateAuthorities/<name>
```

where you fill in project, location and name for the `--gcp_private_ca_parent` flag

This can be any GCP SA that you have credentials to.

We use the default credential helpers so you can authenticate with Workload Identity in a cluster
or Application Default Credentials locally (remember to `gcloud application-default login`).

## SoftHSM configuration

fulcio may also be used with a pkcs11 capable device such as a SoftHSM. You will also need `pkcs11-tool`

On debian you can install the necessary tools with:

```
apt-get install softhsm2 opensc
```

To configure a SoftHSM:

Create a `config/crypto11.conf` file:

```json
{
  "Path" : "/usr/lib/softhsm/libsofthsm2.so",
  "TokenLabel": "fulcio",
  "Pin" : "2324"
}
```

And a `config/softhsm2.cfg`

```
directories.tokendir = /tmp/tokens
objectstore.backend = file
log.level = INFO
```

Make sure `/tmp/tokens` exists

```shell
mkdir /tmp/tokens
```

Export the `config/softhsm2.cfg`

```shell
export SOFTHSM2_CONF=`pwd`/config/softhsm2.cfg
```

### Start a SoftHSM instance

```shell
# Note: these pins match config/crypto11.conf above
softhsm2-util --init-token --slot 0 --label fulcio --pin 2324 --so-pin 2324
```

### Create keys within the SoftHSM

```shell
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --login-type user --keypairgen --id 1 --label PKCS11CA  --key-type EC:secp384r1
```

* Note: you can import existing keys and import using pkcs11-tool, see pkcs11-tool manual for details

### Create a root CA

Now that your keys are generated, you can use the fulcio `createca` command to generate a Root CA. This command
will also store the generated Root CA into the HSM by the delegated id passed to `--hsm-caroot-id`

```shell
fulcio createca --org=acme --country=UK --locality=SomeTown --province=SomeProvince --postal-code=XXXX --street-address=XXXX --hsm-caroot-id 99 --out myrootCA.pem
```

`fulcio createca` will return a root certificate if used with the `-o` flag. If you plan to run fulcio with a CTFE,
then you will need to configure the root certificate as the trust chain. This can be done as follows::

Copy your root certification from the above step `myrootCA.pem` and then set this within your `ct.cfg` as follows:


```json
config {
	log_id: $log_id
	prefix: "test"
	roots_pem_file: "/etc/config/myrootCA.pem"
....
}
```


### Run PKCS11CA

```shell
fulcio serve --ca pkcs11ca --hsm-caroot-id 99
```

> :warning: A SoftHSM does not provide the same security guarantees as hardware based HSM.
> Use for test development purposes only.

---
**NOTE**

fulcioCA has only been validated against a SoftHSM. In theory this should also work with all PKCS11 compliant
HSM's, but to date we have only tested against a SoftHSM.

---

## Testing with the client

The easiest way to test is with [cosign tool](https://github.com/sigstore/cosign)
and using the `--fulcio-url=http://localhost:5555` flag to test against the
localhost server we set up above. A simple test would be something like this:
```
COSIGN_EXPERIMENTAL=1 ./cosign sign --fulcio-url=http://localhost:5555 ghcr.io/vaikas/task-0d6334dfa6713aace72701018aa72314@sha256:bea0dff7f02e43b0d56b3f8c6cf3ffc5de7d16c4ea4536ef2ba4ef79dc390640
```

You should see your browser open, do the oauth dance and then some output like:

```shell
Generating ephemeral keys...
Retrieving signed certificate...
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&<SNIP>.....
```

## Compose

Docker compose can be used to bring up the ct-log server for local testing.
This reuses the trillian components from Rekor.
Make sure you have github.com/sigsture/rekor cloned as well, and in the same
parent directory as `fulcio`.

You will first need to create a trillian tree for the ct_log to use, and place that
tree id in the `ctfe/ct_server.cfg` file.

Then you can bring it all up with:

```
docker-compose -f ../rekor/docker-compose.yml -f docker-compose.yml
```

If it is all working, this should work:

```
ctclient -log_uri http://localhost:6962/test getroots
```

### Secrets

There are some test secrets in `ctfe` for DEVELOPMENT ONLY.
They were generated with:

```shell
openssl ec -in <(openssl ecparam -genkey -name prime256v1) -out privkey.pem -des
openssl ec -in privkey.pem -pubout -out pubkey.pem
```

The password was `foobar` and is stored in the ct_server.cfg file.
