# Running Fulcio on AWS CloudHSM

Fulcio includes support for AWS CloudHSM as a backend for a self-provisioned root CA. This document outlines how it works and how to set it up.

## Background

AWS CloudHSM provides a [PKCS#11 compliant library](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html) for interacting with instances of its CloudHSM product. For the most part, this serves as a drop-in replacement for the [`SoftHSM`](https://github.com/sigstore/fulcio/blob/main/config/crypto11.conf#L2) PKCS#11 library that Fulcio was built upon; as long as keys are set up beforehand, just as Fulcio expects to be done when using SoftHSM, it (mostly) works with no code changes.

The exception is that CloudHSM [does not support certificate storage](https://docs.aws.amazon.com/cloudhsm/latest/userguide/keystore-third-party-tools.html) on their HSMs:

> AWS CloudHSM does not store certificates on the HSM, as certificates are public, non-confidential data.

In its current state, Fulcio does attempt to store the root CA it creates as part of the `createca` command within the HSM it's using, and this causes an error when running with AWS CloudHSM.

Many possible workarounds (and just as many dead ends) for this limitation were explored during development. While those might change in the future, for now, Fulcio includes a simple workaround that allows it to work with CloudHSM: effectively, during root CA creation when running on AWS, instead of attempting to store the root CA in the HSM or in some other certificate storage service, it's just stored on-disk as a PEM file. Then, later on, when running `fulcio serve`, another option is exposed to load the root CA from disk instead of the HSM. This works around the lack of certificate support on AWS' HSMs.

## Setup Guide

AWS provides a rather comprehensive [setup guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html) for getting a CloudHSM instance deployed and setting up an EC2 instance that can interact with it. For a complete setup, you'll want to make sure the CloudHSM Management Utility, Key Management Utility, and CloudHSM's PKCS#11 library are all installed on your EC2 instance.

### Provisioning an HSM and creating a keypair

First, you'll need to make sure your HSM is set up using the Management Utility using [this guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_mgmt_util-getting-started.html). Next, you should provision keys within the HSM for Fulcio to use. Do this with the Key Management Utility:

- Log in: `loginHSM -u CU -s <username> -p <password>`
- Generate a keypair with appropriate label and ID: `genECCKeyPair -i 14 -l PKCS11CA -id 1`

With these steps done, your HSM is set up!

### Setting up Fulcio

Next: clone Fulcio with this patch included onto the EC2 instance that has the AWS PKCS11 library installed. You'll also need to adjust [`config/crypto11.conf`](config/crypto11.conf) as such, in order to make it work with the CloudHSM setup:

```
{
    "Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
    "TokenLabel": "cavium",
    "Pin" : "<username>:<password>"
}
```

The `Path` variable replaces the `softhsm` PKCS11 library with AWS CloudHSM's. On AWS CloudHSM, the `TokenLabel` must always be `cavium` - or things won't work. The `Pin` takes the format of a crypto user and corresponding password on the HSM, as seen [here](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-pin.html).

With this done, you're ready to use Fulcio!

### Usage

Here are some example commands:

```
fulcio createca --org=acme --country=US --locality=SomeTown --province=SomeProvince --postal-code=XXXX --street-address=XXXX --hsm-caroot-id 1 --out myrootCA.pem --hsm=aws`
```

This command creates a new root CA using the private key stored in AWS CloudHSM and stores it in the `myrootCA.pem` file locally.

```
fulcio serve --ca pkcs11ca --hsm-caroot-id 99 --aws-hsm-root-ca-path myrootCA.pem
```

And this command uses the generated `myrootCA.pem` file to run the Fulcio server.
