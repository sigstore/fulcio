// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"os"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	// Register the provider-specific plugins
	"github.com/sigstore/sigstore/pkg/signature/kms"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

/*
To run:
go run cmd/fetch_ca_cert/fetch_ca_cert.go \
  --kms-resource="gcpkms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>/versions/1" \
  --gcp-ca-parent="projects/<project>/locations/<region>/caPools/<ca-pool>" \
  --output="chain.crt.pem"

You must have the permissions to read the KMS key, and create a certificate in the CA pool.
*/

var (
	gcpCaParent = flag.String("gcp-ca-parent", "", "Resource path to GCP CA Service CA")
	kmsKey      = flag.String("kms-resource", "", "Resource path to KMS key, starting with gcpkms://, awskms://, azurekms:// or hashivault://")
	outputPath  = flag.String("output", "", "Path to the output file")
)

func fetchCACertificate(ctx context.Context, parent, kmsKey string, client *privateca.CertificateAuthorityClient) ([]*x509.Certificate, error) {
	kmsSigner, err := kms.Get(ctx, kmsKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	signer, _, err := kmsSigner.CryptoSigner(ctx, func(err error) {})
	if err != nil {
		return nil, err
	}

	pemPubKey, err := cryptoutils.MarshalPublicKeyToPEM(signer.Public())
	if err != nil {
		return nil, err
	}

	isCa := true
	// default value of 0 for int32
	var maxIssuerPathLength int32

	csr := &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			// Default to a very large lifetime - CA Service will truncate the
			// lifetime to be no longer than the root's lifetime.
			// 20 years (24 hours * 365 days * 20)
			Lifetime: durationpb.New(time.Hour * 24 * 365 * 20),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    pemPubKey,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								CertSign: true,
								CrlSign:  true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								CodeSigning: true,
							},
						},
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa:                &isCa,
							MaxIssuerPathLength: &maxIssuerPathLength,
						},
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							CommonName:   "sigstore-intermediate",
							Organization: "sigstore.dev",
						},
					},
				},
			},
		},
	}

	resp, err := client.CreateCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}

	var pemCerts []string
	pemCerts = append(pemCerts, resp.PemCertificate)
	pemCerts = append(pemCerts, resp.PemCertificateChain...)

	var parsedCerts []*x509.Certificate
	for _, c := range pemCerts {
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(c))
		if err != nil {
			return nil, err
		}
		if len(certs) != 1 {
			return nil, errors.New("unexpected number of certificates returned")
		}
		parsedCerts = append(parsedCerts, certs[0])
	}

	return parsedCerts, nil
}

func main() {
	flag.Parse()

	if *gcpCaParent == "" {
		log.Fatal("gcp-ca-parent must be set")
	}
	if *kmsKey == "" {
		log.Fatal("kms-resource must be set")
	}
	if *outputPath == "" {
		log.Fatal("output must be set")
	}

	client, err := privateca.NewCertificateAuthorityClient(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	parsedCerts, err := fetchCACertificate(context.Background(), *gcpCaParent, *kmsKey, client)
	if err != nil {
		log.Fatal(err)
	}
	pemCerts, err := cryptoutils.MarshalCertificatesToPEM(parsedCerts)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*outputPath, pemCerts, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
