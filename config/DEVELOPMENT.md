# Developing Fulcio

Fulcio uses Go and can be run with no other dependencies, other than a trust root PKIX / CA capable system.  Currently
fulcio supports Google certificate authority service (GCP SA)  or a PKCS11 capable HSM (such as SoftHSM).

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

The client here is really only intended to test the `fulcio` server.

It can be run with:

```shell
go run ./cmd/client/
```

The client defaults to a local fulcio at http://127.0.0.1:5555.
This can be overridden with the `--fulcio_address` flag.

You should see your browser open, do the oauth dance and then some output like:

```shell
$ go run ./cmd/client/
Your browser will now be opened to:
https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&client_id=...

-----BEGIN CERTIFICATE-----
MIICyjCCAlCgAwIBAgITEfJ495apY+Xh6mwKJSeVKElaSjAKBggqhkjOPQQDAzAq
MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIx
MDMwNzE0NDU1N1oXDTIxMDMwNzE1MDU1MFowOjEbMBkGA1UECgwSbG9yZW5jLmRA
Z21haWwuY29tMRswGQYDVQQDDBJsb3JlbmMuZEBnbWFpbC5jb20wdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAARGGPRUeASYE7ilcb59Lplt1HS21EktIc3WyUc3rVd17BZ+
OzVKUKlATQ8FZQ1Bcs5KFEQY+gDbSH/jmyA6LqNN1heIBh6vw9AoLQj/uMaocIAs
MkR2gWntT9zf2g8ysGWjggEmMIIBIjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUH4c4aC1y99X3F+Oa
yiwx13lnwjgwHwYDVR0jBBgwFoAUyMUdAEGaJCkyUSTrDa5K7UoG0+wwgY0GCCsG
AQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVu
dC02MDNmZTdlNy0wMDAwLTIyMjctYmY3NS1mNGY1ZTgwZDI5NTQuc3RvcmFnZS5n
b29nbGVhcGlzLmNvbS9jYTM2YTFlOTYyNDJiOWZjYjE0Ni9jYS5jcnQwHQYDVR0R
BBYwFIESbG9yZW5jLmRAZ21haWwuY29tMAoGCCqGSM49BAMDA2gAMGUCMQCsr95C
BNieKlQUj41RB9p4IB2c+8XbMK69jXm6IHZRca65nOP4nMwFUqlE1W/OnlACMAht
LTUlNndCw2IbG027fRqpElrc/IoIDBUa6aW7E1IL6gcnRk3MK38lkAg/jYaucw==
-----END CERTIFICATE-----
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
