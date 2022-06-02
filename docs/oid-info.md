# Sigstore OID information

## Description

Sigstore maintains its own Private Enterprise Number (57264) with the Internet
Assigned Numbers Authority to help identify and organize additional metadata in
code signing certificates issued by Fulcio instances. This document aims to
provide a simple directory of values in use with an explanation of their
meaning.

## Directory

Note that all values begin from the root OID 1.3.6.1.4.1.57264 [registered by
Dan Lorenc][oid-link].

## 1.3.6.1.4.1.57264.1 | Fulcio

The `.1` is added to the root OID for sigstore for all OIDs set by Fulcio.

### 1.3.6.1.4.1.57264.1.1 | Issuer

This contains the `issuer` claim from the OIDC Identity Token that was
presented at the time the code signing certificate was requested to be created.
This claim is the URI of the OIDC Identity Provider that digitally signed the
identity token.

### 1.3.6.1.4.1.57264.1.2 | GitHub Workflow Trigger

This contains the `event_name` claim from the GitHub OIDC Identity token that
contains the name of the event that triggered the workflow run.
[(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.3 | GitHub Workflow SHA

This contains the `sha` claim from the GitHub OIDC Identity token that contains
the commit SHA that the workflow run was based upon. [(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.4 | GitHub Workflow Name

This contains the `workflow` claim from the GitHub OIDC Identity token that
contains the name of the executed workflow. [(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.5 | GitHub Workflow Repository

This contains the `repository` claim from the GitHub OIDC Identity token that
contains the repository that the workflow run was based upon.
[(docs)][github-oidc-doc]

### 1.3.6.1.4.1.57264.1.6 | GitHub Workflow Ref

This contains the `ref` claim from the GitHub OIDC Identity token that contains
the git ref that the workflow run was based upon.
[(docs)][github-oidc-doc]

<!-- References -->
[github-oidc-doc]: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token
[oid-link]: http://oid-info.com/get/1.3.6.1.4.1.57264
