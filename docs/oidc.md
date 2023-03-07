# OIDC Usage in Fulcio

## Summary

Fulcio uses OIDC tokens to authenticate requests. Subject-related claims from the OIDC token are extracted and included in issued certificates.

Sigstore runs a federated OIDC identity provider, Dex. Users authenticate to their preferred identity provider and Dex creates an OIDC token with claims from the original OIDC token. Fulcio also supports OIDC tokens from additional configured issuers.

## Adding a new OIDC issuer

* Add a file under the [`federation` folder](https://github.com/sigstore/fulcio/tree/main/federation) with the URL, new issuer type name, and contact ([example](https://github.com/sigstore/fulcio/blob/8975dfd/federation/agent.buildkite.com/config.yaml))
* Add the new issuer to the [configuration](https://github.com/sigstore/fulcio/blob/main/config/fulcio-config.yaml) by running `go run federation/main.go`
* Add the new issuer to the [`identity` folder](https://github.com/sigstore/fulcio/tree/main/pkg/identity) ([example](https://github.com/sigstore/fulcio/tree/main/pkg/identity/buildkite)). You will define an `Issuer` type and a way to map the token to the certificate extensions.
* Define a constant with the issuer type name in the [configuration](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config.go#L213-L221), add update the [tests](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config_test.go#L473-L503)
* Map the issuer type to the token claim that will be signed over when requesting a token [here](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config.go#L464-L486). You can likely just use `sub`.
* Add a case statement to map the issuer constant to the issuer type you created [here](https://github.com/sigstore/fulcio/blob/4d9d96a/pkg/server/issuer_pool.go#L40-L62)
* Update the end-to-end gRPC tests:
   * Update the [configuration test](https://github.com/sigstore/fulcio/blob/572b7c8496c29a04721f608dd0307ba08773c60c/pkg/server/grpc_server_test.go#L175)
   * Add a test for the new issuer ([example](https://github.com/sigstore/fulcio/blob/572b7c8496c29a04721f608dd0307ba08773c60c/pkg/server/grpc_server_test.go#L331))

See [this example](https://github.com/sigstore/fulcio/pull/890), although it is out of date as you'll now need to create an issuer type.

## Supported OIDC token issuers

### Email

Email-based OIDC providers use the user's email as the subject of the certificate.

* Dex (`oauth2.sigstore.dev/auth`)
    * GitHub (Note that this is the email of the user, not the GitHub username)
    * Google
    * Microsoft
* Google (`accounts.google.com`)

### Source repository

GitHub supports OIDC tokens for its workflows initiated from GitHub Actions. This removes the need for persisting authentication credentials. OIDC tokens include information about the workflow and source repository.

* GitHub Actions (`token.actions.githubusercontent.com`)

### SPIFFE

SPIFFE-based OIDC providers use a SPIFFE ID as the URI subject alternative name of the certificate, scoped to a domain.

* vcr.pub OCI registry (`allow.pub`)

### Kubernetes

Cloud-based Kubernetes instances can authenticate using OIDC tokens per cluster.

* AWS
* Azure
* Google Cloud

## OIDC token requirements with extracted claims

Certificate background: Identities for a certificate are included in the [subject alternative name (SAN)](https://en.wikipedia.org/wiki/Subject_Alternative_Name) field. Fulcio includes email addresses and URIs in the SAN field.

OIDC token: OIDC tokens are JWTs. At a minimum, all tokens must include the following claims:

* Audience (`aud`), set to "sigstore"
* Issuer (`iss`), set to one of the URIs in the Fulcio configuration
* Expiration (`exp`)
* Issued At (`iat`)

For example, `iss` could be `https://oauth2.sigstore.dev/auth` or `https://token.actions.githubusercontent.com`.

```json
{
    "aud": "sigstore",
    "iss": "<uri>",
    "exp": "<timestamp>",
    "iat": "<timestamp>"
}
```

If the issuer is in a different claim than `iss`, then you can include `IssuerClaim` in the Fulcio OIDC configuration to specify the JSON path to the issuer.

### Email

In addition to the standard JWT claims, the token must include the following claims:

```json
{
    "email_verified": true,
    "email": "user@example.com"
}
```

`email` is extracted and included as a SAN email address.

### GitHub

The token must include the following claims:

```json
{
    "job_workflow_ref": "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
    "sha": "example-sha",
    "event_name": "workflow_dispatch",
    "repository": "octo-org/octo-repo",
    "workflow": "example-workflow",
    "ref": "refs/heads/main",
}
```

`job_workflow_ref` is included as a SAN URI: `https://github.com/{job_workflow_ref}`

All other required claims are extracted and included in custom OID fields, as documented in [OID Information](oid-info.md).

### SPIFFE

The token must include the following claims:

```json
{
    "sub": "spiffe://foo.example.com"
}
```

The configuration must include `SPIFFETrustDomain`, for example `example.com`. Tokens must conform to the following:

* The trust domain of the configuration and hostname of `sub` must match exactly.

`sub` is included as a SAN URI.

### Kubernetes

The token must include the following claims:

```json
{
    "kubernetes.io": {
	    "namespace": "default",
	    "pod": {
	        "name": "oidc-test",
	        "uid": "49ad3572-b3dd-43a6-8d77-5858d3660275"
	    },
	    "serviceaccount": {
	        "name": "default",
	        "uid": "f5720c1d-e152-4356-a897-11b07aff165d"
	    }
	}
}
```

These claims are used to form the SAN URI of the certificate: `https://kubernetes.io/namespaces/{claims.kubernetes.namespace}/serviceaccounts/{claims.kubernetes.serviceAccount.name}`

### URI

The token must include the following claims:

```json
{
    "sub": "https://example.com/users/1"
}
```

Additionally, the configuration must include `SubjectDomain`, for example `https://example.com`. Tokens must conform to the following:

* The issuer in the configuration must partially match the domain in the configuration. The scheme, top level domain, and second level domain must match. The user who updates the Fulcio configuration must also have control over both the issuer and domain configuration fields (Verified either manually or through an ACME-style challenge).
* The domain of the configuration and hostname of the subject of the token must match exactly.

`sub` is included as a SAN URI.
 
### Username

The token must include the following claims:

```json
{
    "sub": "exampleUsername"
}
```

Additionally, the configuration must include `SubjectDomain`, for example `example.com`. Tokens must conform to the following:

* The issuer in the configuration must partially match the domain in the configuration. The top level domain and second level domain must match. The user who updates the Fulcio configuration must also have control over both the issuer and domain configuration fields (Verified either manually or through an ACME-style challenge).

`SubjectDomain` is appended to `sub` to form an identity, `sub!SubjectDomain`, and included as an OtherName SAN.

### Buildkite

The token must include the following claims:

```json
{
    "sub": "organization:acme-inc:pipeline:super-duper-app:ref:refs/heads/main:commit:9f3182061f1e2cca4702c368cbc039b7dc9d4485:step:",
    "organization_slug": "acme-inc",
    "pipeline_slug": "super-duper-app"
}
```

These claims are used to form the SAN URI of the certificate: `https://buildkite.com/acme-inc/super-duper-app`.