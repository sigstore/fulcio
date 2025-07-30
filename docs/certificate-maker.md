# Certificate Maker

This tool creates certificates (root, intermediate, and leaf) that meet Fulcio's ([certificate requirements](certificate-specification.md)).

It relies on [x509util](https://pkg.go.dev/go.step.sm/crypto/x509util) which builds X.509 certificates from JSON templates. The tool includes embedded default templates that are compiled into the binary, making it ready to use without external template files.

## Requirements

- Access to one of the supported KMS providers (AWS, Google Cloud, Azure, HashiCorp Vault)
- Pre-existing KMS keys (the tool uses existing keys and does not create new ones)

## Local Development

Build the binary:

```bash
make cert-maker
./certificate-maker --help
```

## Usage

The tool can be configured using either command-line flags or environment variables.

### Command-Line Interface

The `create` command accepts an optional positional argument for the common name:

```bash
./certificate-maker create [common-name]
```

If no common name is provided, the values from the templates will be used.

Available flags:

- `--kms-type`: KMS provider type (awskms, gcpkms, azurekms, hashivault)

- `--root-key-id`: KMS key identifier for root certificate
- `--intermediate-key-id`: KMS key identifier for intermediate certificate
- `--leaf-key-id`: KMS key identifier for leaf certificate

- `--aws-region`: AWS region (required for AWS KMS)
- `--azure-tenant-id`: Azure KMS tenant ID
- `--gcp-credentials-file`: Path to credentials file (for Google Cloud KMS)
- `--vault-address`: HashiCorp Vault address
- `--vault-token`: HashiCorp Vault token
- `--vault-namespace`: HashiCorp Vault namespace (for Vault Enterprise)

- `--root-template`: Path to root certificate template
- `--root-lifetime`: Root certificate lifetime (default: 87600h, 10 years)
- `--root-cert`: Output path for root certificate (default: root.pem)

- `--intermediate-template`: Path to intermediate certificate template
- `--intermediate-cert`: Output path for intermediate certificate
- `--intermediate-lifetime`: Intermediate certificate lifetime (default: 43800h, 5 years)

- `--leaf-template`: Path to leaf certificate template
- `--leaf-cert`: Output path for leaf certificate (default: leaf.pem)
- `--leaf-lifetime`: Leaf certificate lifetime (default: 8760h, 1 year)

### Environment Variables

- `KMS_TYPE`: KMS provider type ("awskms", "gcpkms", "azurekms", "hashivault")

- `ROOT_KEY_ID`: Key identifier for root certificate
- `KMS_INTERMEDIATE_KEY_ID`: Key identifier for intermediate certificate
- `LEAF_KEY_ID`: Key identifier for leaf certificate

- `AWS_REGION`: AWS Region (required for AWS KMS)

- `AZURE_TENANT_ID`: Azure tenant ID

- `GCP_CREDENTIALS_FILE`: Path to credentials file (for Google Cloud KMS)

- `VAULT_ADDR`: HashiCorp Vault address
- `VAULT_TOKEN`: HashiCorp Vault token
- `VAULT_NAMESPACE`: HashiCorp Vault namespace (if using Vault Enterprise with namespaces)

### Certificate Templates

The embedded templates are located in `pkg/certmaker/templates/` in the source code and are compiled into the binary. You can override these defaults by providing your own template files using:

- `--root-template`: Custom root CA template
- `--intermediate-template`: Custom intermediate CA template  
- `--leaf-template`: Custom leaf template

If no custom templates are provided via flags, the tool will automatically use the embedded defaults which are designed to work with Fulcio's certificate requirements as long as the intended common name is used as a positional argument.

More info on configuring templates can be found here:

- [X.509 Templates](https://smallstep.com/docs/step-ca/templates/#x509-templates)

### Provider-Specific Configuration Examples

#### AWS KMS

```shell
export KMS_TYPE=awskms
export AWS_REGION=us-east-1
export ROOT_KEY_ID=alias/root-key
export KMS_INTERMEDIATE_KEY_ID=alias/intermediate-key
export LEAF_KEY_ID=alias/leaf-key
```

#### Google Cloud KMS

```shell
export KMS_TYPE=gcpkms
export ROOT_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
export LEAF_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
export KMS_INTERMEDIATE_KEY_ID=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY_NAME/cryptoKeyVersions/VERSION
```

#### Azure KMS

```shell
export KMS_TYPE=azurekms
export ROOT_KEY_ID=azurekms:name=root-key;vault=fulcio-keys
export KMS_INTERMEDIATE_KEY_ID=azurekms:name=leaf-key;vault=fulcio-keys
export LEAF_KEY_ID=azurekms:name=leaf-key;vault=fulcio-keys
export AZURE_TENANT_ID=83j229-83j229-83j229-83j229-83j229
```

#### HashiCorp Vault KMS

```shell
export KMS_TYPE=hashivault
# Key IDs should be just the key name, not the full transit path
export ROOT_KEY_ID=root-key
export KMS_INTERMEDIATE_KEY_ID=intermediate-key
export LEAF_KEY_ID=leaf-key
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=your-vault-token
# Optional: Set namespace if using Vault Enterprise
export VAULT_NAMESPACE=admin/your-namespace
```

**Important Notes for HashiVault:**

- Key IDs should be just the key name (e.g., `root-key`), not the full transit path (`transit/keys/root-key`)
- The Sigstore library automatically constructs the full path internally
- Use HTTPS for production Vault deployments
- Set `VAULT_NAMESPACE` if your keys are in a specific Vault namespace
- Ensure your Vault token has the following permissions:
  - `read` capability on `transit/keys/<key-name>` (to fetch public keys)
  - `update` capability on `transit/sign/<key-name>` (to perform signing operations)

### Example Certificate Outputs

#### Fulcio Leaf Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012039 (0x674baa47)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Fulcio Intermediate CA, CN=https://fulcio.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Fulcio Leaf CA, CN=https://fulcio.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f8:ca:84:0d:9d:31:da:d0:94:1f:2a:53:ff:3f:
                    f2:39:ca:90:5b:8c:26:29:28:02:a7:e2:10:80:92:
                    1b:9f:3a:03:c7:cd:36:7a:2c:2b:1c:0c:95:bc:86:
                    73:b4:55:46:0e:50:29:34:1e:07:a6:64:41:13:ca:
                    36:5d:d4:71:dd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
            X509v3 Authority Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:e5:98:16:cd:93:2c:20:73:e3:b6:62:4a:25:
        40:c0:e0:68:fb:4a:70:ce:89:09:6c:cd:b6:c6:2c:ee:66:40:
        6f:02:21:00:eb:b7:53:99:60:2a:92:d2:90:39:73:f8:98:18:
        96:2c:fe:cb:ac:5b:63:36:fe:5d:75:9b:da:69:b9:9b:c6:fb
```

#### Fulcio Intermediate CA Certificate

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012039 (0x674baa47)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Fulcio Intermediate CA, CN=https://fulcio.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:f8:ca:84:0d:9d:31:da:d0:94:1f:2a:53:ff:3f:
                    f2:39:ca:90:5b:8c:26:29:28:02:a7:e2:10:80:92:
                    1b:9f:3a:03:c7:cd:36:7a:2c:2b:1c:0c:95:bc:86:
                    73:b4:55:46:0e:50:29:34:1e:07:a6:64:41:13:ca:
                    36:5d:d4:71:dd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier:
                0D:1B:3F:95:18:04:65:60:AD:E3:28:D0:B7:43:45:BD:FE:63:5A:DF
            X509v3 Authority Key Identifier:
                BB:84:41:46:F0:A6:90:38:C0:73:1E:11:F4:58:7C:44:9B:C6:45:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:88:2b:2a:68:f1:61:34:4b:e5:f2:24:26:3c:
        64:1c:80:94:94:02:e1:78:a1:ea:6c:1b:92:a7:54:b2:88:52:
        90:02:21:00:a6:7d:ef:04:ba:2a:5b:a9:f6:b7:c8:02:1e:9f:
        78:2c:15:09:bd:b3:93:d9:6b:b2:ba:43:6e:b9:61:61:ea:8a
```

#### Fulcio Root CA Certificate

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1733012038 (0x674baa46)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        Validity
            Not Before: Jan  1 00:00:00 2024 GMT
            Not After : Jan  1 00:00:00 2034 GMT
        Subject: C=US, O=Sigstore, OU=Fulcio Root CA, CN=https://fulcio.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:73:77:29:2b:48:de:da:82:53:60:36:ac:9e:b7:
                    e1:78:3e:e1:d6:58:f1:7e:fa:b2:2a:28:c5:c8:d4:
                    25:c6:e8:5c:d1:63:a8:22:3e:a6:7b:bb:3b:d7:f3:
                    98:c8:25:52:12:2a:c1:fb:9b:56:af:97:77:a4:48:
                    89:be:49:bc:63
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier:
                BB:84:41:46:F0:A6:90:38:C0:73:1E:11:F4:58:7C:44:9B:C6:45:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:d5:82:3b:01:64:9f:f3:f3:b1:d6:44:43:1f:
        78:2d:7f:b8:c9:e9:0e:7e:34:9f:8c:55:33:09:14:2a:16:c5:
        b2:02:20:04:a5:a2:49:ee:3b:22:4c:f5:5b:b3:9b:ff:b4:40:
        dc:f6:a3:11:00:05:a3:14:d5:77:72:f6:f9:44:f1:e9:27
```

## Running the Tool

Example with AWS KMS:

```bash
./certificate-maker create "https://fulcio.example.com" \
  --kms-type awskms \
  --aws-region us-east-1 \
  --root-key-id alias/fulcio-root \
  --leaf-key-id alias/fulcio-leaf \
  --root-template pkg/certmaker/templates/root-template.json \
  --leaf-template pkg/certmaker/templates/leaf-template.json \
  --root-lifetime 87600h \
  --leaf-lifetime 8760h
```

Example with Azure KMS:

```bash
./certificate-maker create "https://fulcio.example.com" \
  --kms-type azurekms \
  --azure-tenant-id 1b4a4fed-fed8-4823-a8a0-3d5cea83d122 \
  --root-key-id "azurekms:name=sigstore-key;vault=sigstore-key" \
  --leaf-key-id "azurekms:name=sigstore-key-intermediate;vault=sigstore-key" \
  --intermediate-key-id "azurekms:name=sigstore-key-intermediate;vault=sigstore-key" \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem \
  --root-lifetime 87600h \
  --intermediate-lifetime 43800h \
  --leaf-lifetime 8760h
```

Example with GCP KMS:

```bash
./certificate-maker create "https://fulcio.example.com" \
  --kms-type gcpkms \
  --gcp-credentials-file ~/.config/gcloud/application_default_credentials.json \
  --root-key-id  projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --intermediate-key-id projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --leaf-key-id projects/<project_id>/locations/<location>/keyRings/<keyring>/cryptoKeys/fulcio-key1/cryptoKeyVersions/<version> \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem \
  --root-lifetime 87600h \
  --intermediate-lifetime 43800h \
  --leaf-lifetime 8760h
```

Example with HashiCorp Vault KMS:

```bash
# Set environment variables (recommended approach)
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=your-vault-token
# Optional: Set namespace if using Vault Enterprise
export VAULT_NAMESPACE=admin/your-namespace

# Run the certificate maker
./certificate-maker create "https://fulcio.example.com" \
  --kms-type hashivault \
  --root-key-id "root-key" \
  --leaf-key-id "leaf-key" \
  --intermediate-key-id "intermediate-key" \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem \
  --root-lifetime 87600h \
  --intermediate-lifetime 43800h \
  --leaf-lifetime 8760h
```

**Alternative with command-line flags:**

```bash
./certificate-maker create "https://fulcio.example.com" \
  --kms-type hashivault \
  --vault-address https://vault.example.com:8200 \
  --vault-token your-vault-token \
  --vault-namespace admin/your-namespace \
  --root-key-id "root-key" \
  --leaf-key-id "leaf-key" \
  --intermediate-key-id "intermediate-key" \
  --root-cert root.pem \
  --leaf-cert leaf.pem \
  --intermediate-cert intermediate.pem \
  --root-lifetime 87600h \
  --intermediate-lifetime 43800h \
  --leaf-lifetime 8760h
```
