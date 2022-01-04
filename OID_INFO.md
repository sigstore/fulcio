# sigstore OID Information

## Description

sigstore maintains its own Private Enterprise Number (57264) with the Internet Assigned Numbers Authority to help identify and organize additional metadata in code signing certificates issued by Fulcio instances. This document aims to provide a simple directory of values in use with an explanation of their meaning.

## Directory

Note that all values begin from the root OID 1.3.6.1.4.1.57264 [registered by Dan Lorenc](http://oid-info.com/get/1.3.6.1.4.1.57264):

# 1.3.6.1.4.1.57264.1 (Fulcio)
- *1.3.6.1.4.1.57264.1.1*: (Issuer)
    - This contains the `issuer` claim from the OIDC Identity Token that was presented at the time the code signing certificate was requested to be created. This claim is the URI of the OIDC Identity Provider that digitally signed the identity token.
- *1.3.6.1.4.1.57264.1.2*: (GithubWorkflowTrigger)
    - This contains the `event_name` claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run. [(docs)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
- *1.3.6.1.4.1.57264.1.3*: (GithubWorkflowSha)
    - This contains the `sha` claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon. [(docs)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
- *1.3.6.1.4.1.57264.1.4*: (GithubWorkflowName)
    - This contains the `workflow` claim from the GitHub OIDC Identity token that contains the name of the executed workflow. [(docs)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
- *1.3.6.1.4.1.57264.1.5*: (GithubWorkflowRepository)
    - This contains the `repository` claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon. [(docs)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
- *1.3.6.1.4.1.57264.1.6*: (GithubWorkflowRef)
    - This contains the `ref` claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon. [(docs)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
