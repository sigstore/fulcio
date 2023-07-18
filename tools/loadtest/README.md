# Fulcio Performance Test

## Overview

[Learn more about Locust](http://docs.locust.io/en/stable/index.html).

1. Install Locust with `pip3 install -r requirements.txt`
1. Fetch an identity token for a service account with `gcloud auth print-identity-token --audiences sigstore --impersonate-service-account <name>@<project-id>.iam.gserviceaccount.com --include-email`.
1. Start `locust`, configuring number of users, spawn rate, host, maximum QPS per user, and identity token.

## Prerequisites

You will need Python 3 to install the Python requirements.

You will also need to set up a GCP project with a single service account. The service account will be used to generate an identity token for calls to Fulcio.

## Running Locust

### Installation

Run `pip3 install -r requirements.txt`, which will install Locust and necessary libraries.

Confirm a successful install with `locust -V`, which should print the version. You may need to include `~/.local/bin` in your PATH.

### Fetching identity token

To fetch a certificate, you will need an OIDC token from one of the [OIDC issuers](https://github.com/sigstore/fulcio/blob/main/config/fulcio-config.yaml). One way is to fetch a token from Google. Note that you will need to install [`gcloud`](https://cloud.google.com/sdk/gcloud) and create a service account. A service account is necessary for the `--include-email` flag, which is needed to get an OIDC token with the correct format for Fulcio.

Run the following command, and record the output:

`gcloud auth print-identity-token --audiences sigstore --impersonate-service-account <name>@<project-id>.iam.gserviceaccount.com --include-email`

Note that this token will be valid for approximately one hour.

### Configuring maximum QPS per user

You can configure the test to set a maximum QPS per user. This will limit each Locust user to the specified QPS. Without this, Locust will generate an unbounded amount of traffic. You can choose to remove `wait_time` if you want this behavior, but be careful to not overwhelm a production instance.

### Running test

From within the directory with `locustfile.py`, run the command `locust`. Open `localhost:8089` in a browser. Note you can also run `locust` from the command line, see the [documentation](http://docs.locust.io/en/stable/configuration.html#configuration).

From the browser, set the following:
* Number of users. Each will run at a maximum QPS based on maximum QPS set below.
* Spawn rate, how often users are created per second
* Host, e.g. `localhost:port`. Please do not run against production or staging.
* Token - The identity token from `gcloud auth`
* Max QPS per user

Click 'Start Swarming', and monitor for errors.

## Results (12/14/21)

https://github.com/sigstore/fulcio/issues/193#issuecomment-994247492
