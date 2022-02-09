# Feature Stability

This doc covers feature stability in `fulcio` as described in the [API Stability Policy](https://docs.sigstore.dev/api-stability) for Sigstore.

## Experimental


## Beta
* The Fulcio API, defined [here](https://github.com/sigstore/fulcio/blob/main/pkg/api/client.go)
* Support for various Certificate Authorities (CAs), including Google Private CA Service, PKCS11, and File backed CA
* Support for SPIFFE challenges and OIDC based email challenges
* The Go client library defined in `fulcio/pkg`
* Issuers defined in [fulcio-config.yaml](https://github.com/sigstore/fulcio/blob/main/config/fulcio-config.yaml)

## General Availability
