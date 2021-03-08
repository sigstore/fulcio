# Developing Fulcio

Fulcio uses Go and can be run with no other dependencies, other than a GCP CA.

You can run locally (outside a container) with:

```
go run ./cmd/server/ serve --port 5555 --gcp_private_ca_parent=projects/<project>/locations/<location>/certificateAuthorities/<name>
```

where you fill in project, location and name for the `--gcp_private_ca_parent` flag

This can be any GCP SA that you have credentials to.
We use the default credential helpers so you can authenticate with Workload Identity in a cluster
or Application Default Credentials locally (remember to `gcloud application-default login`).

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
