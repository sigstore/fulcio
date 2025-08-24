# OIDC Usage in Fulcio

## Summary

Fulcio uses OIDC tokens to authenticate requests. Subject-related claims from the OIDC token are extracted and included in issued certificates.

Sigstore runs a federated OIDC identity provider, Dex. Users authenticate to their preferred identity provider and Dex creates an OIDC token with claims from the original OIDC token. Fulcio also supports OIDC tokens from additional configured issuers.

## Integration Guide

To add a new OIDC issuer:

* Add the new issuer to the [configuration](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml).
  * Attention: If your issuer is for a CI provider, you should set the `type` as `ci-provider` and set the field `ci-provider` with the name of your provider. You should also fill the `ci-issuer-metadata` with the `default-template-values`, `extension-templates` and `subject-alternative-name-template`, following the pattern defined on the [example](https://github.com/sigstore/fulcio/commit/9f02ba2924c6f8a0b46861b3585cb497a7560454).
  * Important notes: The `extension-templates` and the `subject-alternative-name-template` follows the templates [pattern](https://pkg.go.dev/text/template). The name used to fill the `ci-provider` field has to be the same used as key for `ci-issuer-metadata`, we suggest to use a variable for this. If you set a `default-template-value` with the same name of a claim key, the claimed value will have priority over the default one.
* If your issuer is not for a CI provider, you need to follow the next steps:
  * Add the new issuer to the [`identity` folder](https://github.com/sigstore/fulcio/tree/main/pkg/identity) ([example](https://github.com/sigstore/fulcio/tree/main/pkg/identity/email)). You will define an `Issuer` type and a way to map the token to the certificate extensions.
  * Define a constant with the issuer type name in the [configuration](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config.go#L213-L221), add update the [tests](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config_test.go#L473-L503)
  * Map the issuer type to the token claim that will be signed over when requesting a token [here](https://github.com/sigstore/fulcio/blob/afeadb3b7d11f704489637cabc4e150dea3e00ed/pkg/config/config.go#L464-L486). You can likely just use `sub`.
  * Add a case statement to map the issuer constant to the issuer type you created [here](https://github.com/sigstore/fulcio/blob/4d9d96a/pkg/server/issuer_pool.go#L40-L62)
* These next steps are required only for non-ci issuers, as it is already tested for generically. Although, you are welcome to add tests for your provider if you want to.
  * Update the end-to-end gRPC tests:
    * Update the [configuration test](https://github.com/sigstore/fulcio/blob/572b7c8496c29a04721f608dd0307ba08773c60c/pkg/server/grpc_server_test.go#L175)
    * Add a test for the new issuer ([example](https://github.com/sigstore/fulcio/blob/572b7c8496c29a04721f608dd0307ba08773c60c/pkg/server/grpc_server_test.go#L331))

See [this example](https://github.com/sigstore/fulcio/pull/890), although it is out of date as you'll now need to create an issuer type.

## Authorization rules

Fulcio supports optional claims-based authorization that can be configured per OIDC issuer to restrict certificate issuance based on token claims.

### Configuration

Authorization rules are configured in the `authorization-rules` section of each OIDC issuer:

```yaml
oidc-issuers:
  https://token.actions.githubusercontent.com:
    issuer-url: https://token.actions.githubusercontent.com
    client-id: sigstore
    type: github-workflow
    authorization-rules:
      - name: "Allow specific repositories"
        logic: "AND"
        conditions:
          - field: "repository_owner"
            pattern: "^myorg$"
          - field: "repository"
            pattern: "^myorg/(prod-api|staging-api)$"
```

### Rule evaluation

- Rules are evaluated after successful OIDC authentication
- If ANY rule matches, authorization passes
- If NO rules match, authorization fails (HTTP 403)
- If NO rules are configured, authorization is skipped

### Common patterns

Note: we assume that the OIDC tokens expose the claims used in those examples.

**Repository-based access**:
```yaml
authorization-rules:
  - name: "Production repositories"
    logic: "AND"
    conditions:
      - field: "repository_owner"
        pattern: "^myorg$"
      - field: "repository"
        pattern: "^myorg/(api|web|mobile)$"
```

**User-based access**:
```yaml
authorization-rules:
  - name: "Admin users"
    logic: "OR"
    conditions:
      - field: "role"
        pattern: "^administrator$"
      - field: "sub"
        pattern: "^admin@myorg\\.com$"
```

**Environment-based access**:
```yaml
authorization-rules:
  - name: "Production deployments"
    logic: "AND"
    conditions:
      - field: "environment"
        pattern: "^production$"
```

### Security considerations

- **Fail-secure by design**: Invalid authorization configurations prevent server startup
- **No fallback behavior**: Malformed authorization rules never default to allow-all access
- **Authorization provides defense in depth beyond OIDC authentication** (suitable for private deployments)
- **Rules use Go regex patterns** (safe from ReDoS attacks)
- **All authorization decisions are logged for audit**
- **Failed authorization does not reveal token claims in responses**

See [Authorization documentation](authorization.md) for comprehensive configuration examples and security guidance.

### How to pick a SAN

SANs are important for users to describe identities across platforms. They are
used in verification policies as the primary identifier for a workload.

Unfortunately there's no one size fits all answer for how to pick the best SAN
to use for your service. To help, here are a few things to consider when making
this choice:

- How will users want to query / write policy for artifacts?

  Consider what resource(s) users will want to query against. How would they
  distinguish resources between different teams? Production vs staging?

  💡 Litmus test: what value is appropriate for
  `cosign verify --certificate-identity=<?>`

- What's the most-specific identifier that can describe the workload?

  Choosing a SAN is often similar to figuring out what service account your
  workloads should have. Too broad, you may give unintended access to workloads
  that don't need it. Too narrow, and you end up having to manage the same
  permissions across multiple accounts.

- Will the identifier change per-instance?

  Identifiers that are based on UUIDs and can change each instance do not make
  good SANs. They tend to be too narrow and make it difficult to write a policy
  that will work consistently. If you need to reach for a regex for most
  policies, your SAN is probably too specific.

- Can the identifier collide with other resources?

  SANs should be unique for the issuer. Resources should not have the ability to
  use or craft a SAN of another resource.

- Is the identifier well-defined?

  All SANs for a provider should be defined and documented. If an issuer has the
  ability to produce different SANs, differences and conditions for these SANs
  should be documented.

#### Case study: GitHub Actions

GitHub Actions uses the `job_workflow_ref` as its SAN. This has a few nice
properties when working with GitHub Actions:

- It's tied to a particular Job in a workflow.
- It can identify reusable workflows for common shared behavior, so multiple teams
  relying on the same reusable workflow can also share policies.
- The ref included can be used to verify it's coming from the expected location
  and not a branch.

To understand some of the considerations, below are some reasons for why values were
**not** used as the SAN:

- GitHub Repository

  Example: `https://github.com/foo/bar`

  Too broad - this could apply to any GitHub Action in the repo (even
  potentially from pull requests).

- [Subject](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims)

  Example: `repo:foo/bar:ref:refs/heads/main`

  Slightly too broad - the most specific you can get with a GitHub Subject is
  the event type + ref. Users may want to distinguish between different
  workflows.

- GitHub Action Job ID

  Example: `https://github.com/foo/bar/repo/actions/runs/4725056848/jobs/8382992120`

  Too narrow.

  Every GitHub Action has a unique job id that it can use to uniquely identify
  each run of a Job.

  While this gives you a specific identifier, it is not stable and changes for
  every run. Most users would likely reach for a policy that matches a broader
  set of jobs `https://github.com/org/repo/.*`, which makes it impractical to
  use as a specific identifier.

- GitHub Workflow Ref

  Example: `foo/bar/.github/workflows/my-workflow.yml@refs/heads/main`

  Slightly too narrow.

  [Workflows](https://docs.github.com/en/actions/using-workflows/about-workflows)
  are the entrypoints to GitHub Actions - they define the trigger conditions and
  configuration for what will run.

  Workflows may end up using the same underlying job configuration
  with some minor tweaks (e.g. permissions, inputs, etc) by using
  [reusable Workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows).
  Instead of requiring different policies for each workflow that modify how the same
  reusable workflow is invoked, the job_workflow_ref is used instead to allow users
  to centralize these policies under the same SAN.

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

### GitLab

The token must include the following claims:

```json
{
    "namespace_id": "72",
    "namespace_path": "my-group",
    "project_id": "20",
    "project_path": "my-group/my-project",
    "pipeline_id": "574",
    "pipeline_source": "push",
    "job_id": "302",
    "ref": "main",
    "ref_type": "branch",
    "runner_id": 1,
    "runner_environment": "gitlab-hosted",
    "sha": "714a629c0b401fdce83e847fc9589983fc6f46bc",
    "project_visibility": "public",
    "ci_config_ref_uri": "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main"
}
```

`ci_config_ref_uri` is included as a SAN URI: `https://{ci_config_ref_uri}`

All other required claims are extracted and included in custom OID fields, as documented in [OID Information](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#mapping-oidc-token-claims-to-fulcio-oids).


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
