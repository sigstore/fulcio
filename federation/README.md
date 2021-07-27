# OIDC Federation Configs

This directory contains configurations for individual OIDC endpoints that the public good instance of Fulcio should accept identity tokens from.

## Usage

To update the k8s `ConfigMap`, run `go run federation/main.go` from the root directory of this repository.

## Adding New Entries

We'll happily accept new entries here in the form of a pull request!
Open one up with your endpoint, filling in a directory and a `config.yaml` with the following structure:

```yaml
url: <discovery url>
contact: <your contact email>
description: <a description of the use case>
type: <spiffe|email>
```

You'll then have to regenerate the ConfigMap with `go run federation/main.go`, and then send your PR.

We'll discuss your use-case with you over the pull request, and merge!
