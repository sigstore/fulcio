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

package intermediateca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// TODO: Takes signer (KMS/on-disk/in-memory) and way to fetch intermediate CA cert + chain

type intermediateCA struct {
	sync.RWMutex

	// certs is a chain of certificates from intermediate to root
	certs  []*x509.Certificate
	signer crypto.Signer

	// GCP CA Service
	parent string
	client *privateca.CertificateAuthorityClient

	updatedCerts chan []*x509.Certificate
}

func fetchCACertificate(ctx context.Context, parent string, client *privateca.CertificateAuthorityClient, signer crypto.Signer) ([]*x509.Certificate, error) {
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
			// Two week lifetime for CA certificate
			Lifetime: durationpb.New(time.Hour * 24 * 14),
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
	log.Logger.Info("Current CA certificate chain:")
	log.Logger.Info(pemCerts)

	return parsedCerts, nil
}

func refreshCACertificate(ctx context.Context, ica *intermediateCA) {
	ticker := time.NewTicker(time.Hour * 4)
	for range ticker.C {
		ica.RLock()
		currentCert := ica.certs[0]
		ica.RUnlock()

		// Refresh certificate 7 days before expiration
		if time.Until(currentCert.NotAfter) < (time.Hour * 24 * 7) {
			certs, err := fetchCACertificate(ctx, ica.parent, ica.client, ica.signer)
			if err != nil {
				// An intermittent error is acceptable
				log.Logger.Error(err)
				continue
			}
			ica.updatedCerts <- certs
		}
	}
}

func updateCACertificate(ica *intermediateCA) {
	for certs := range ica.updatedCerts {
		ica.Lock()
		ica.certs = certs
		ica.Unlock()
	}
}

func NewIntermediateCA(ctx context.Context, parent string) (ca.CertificateAuthority, error) {
	var ica intermediateCA

	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		return nil, err
	}
	ica.signer = signer

	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return nil, err
	}
	ica.client = client
	ica.parent = parent

	ica.certs, err = fetchCACertificate(ctx, ica.parent, ica.client, ica.signer)
	if err != nil {
		return nil, err
	}

	ica.updatedCerts = make(chan []*x509.Certificate)

	// Start goroutine to periodically check and refresh CA certificate and chain
	go refreshCACertificate(ctx, &ica)
	// Start goroutine to update CA certificate and chain
	go updateCACertificate(&ica)

	return &ica, nil
}

func (ica *intermediateCA) CreateCertificate(ctx context.Context, challenge *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	cert, err := x509ca.MakeX509(challenge)
	if err != nil {
		return nil, err
	}

	parentCA, privateKey := ica.getX509KeyPair()

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCA, challenge.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	ica.RLock()
	defer ica.RUnlock()
	return ca.CreateCSCFromDER(challenge, finalCertBytes, ica.certs)
}

func (ica *intermediateCA) Root(ctx context.Context) ([]byte, error) {
	ica.RLock()
	defer ica.RUnlock()

	return cryptoutils.MarshalCertificatesToPEM(ica.certs)
}

func (ica *intermediateCA) getX509KeyPair() (*x509.Certificate, crypto.Signer) {
	ica.RLock()
	defer ica.RUnlock()
	return ica.certs[0], ica.signer
}
