// Copyright 2021 The Sigstore Authors.
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

package v1

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

type CertAuthorityService struct {
	parent string
	client *privateca.CertificateAuthorityClient
}

func NewCertAuthorityService(ctx context.Context, parent string) (*CertAuthorityService, error) {
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return nil, err
	}
	return &CertAuthorityService{
		parent: parent,
		client: client,
	}, nil
}

// getPubKeyFormat Returns the PublicKey KeyFormat required by gcp privateca.
// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1#PublicKey_KeyType
func getPubKeyFormat(pemBytes []byte) (privatecapb.PublicKey_KeyFormat, error) {
	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse public key: " + err.Error())
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return privatecapb.PublicKey_PEM, nil
	default:
		return 0, fmt.Errorf("unknown public key type: %v", pub)
	}
}

func convertID(id asn1.ObjectIdentifier) []int32 {
	nid := make([]int32, 0, len(id))
	for _, digit := range id {
		nid = append(nid, int32(digit))
	}
	return nid
}

func Req(parent string, pemBytes []byte, cert *x509.Certificate) (*privatecapb.CreateCertificateRequest, error) {
	// TODO, use the right fields :)
	pubkeyFormat, err := getPubKeyFormat(pemBytes)
	if err != nil {
		return nil, err
	}

	// Translate the x509 certificate's subject to Google proto.
	subject := &privatecapb.CertificateConfig_SubjectConfig{
		Subject: &privatecapb.Subject{
			Organization: "sigstore",
		},
		SubjectAltName: &privatecapb.SubjectAltNames{
			EmailAddresses: cert.EmailAddresses,
		},
	}
	for _, uri := range cert.URIs {
		subject.SubjectAltName.Uris = append(subject.SubjectAltName.Uris, uri.String())
	}

	extensions := make([]*privatecapb.X509Extension, 0, len(cert.ExtraExtensions))
	for _, ext := range cert.ExtraExtensions {
		extensions = append(extensions, &privatecapb.X509Extension{
			ObjectId: &privatecapb.ObjectId{
				ObjectIdPath: convertID(ext.Id),
			},
			Value: ext.Value,
		})
	}

	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(time.Until(cert.NotAfter)),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: pubkeyFormat,
						Key:    pemBytes,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								CodeSigning: true,
							},
						},
						AdditionalExtensions: extensions,
					},
					SubjectConfig: subject,
				},
			},
		},
	}, nil
}

func (c *CertAuthorityService) CreateCertificate(ctx context.Context, subj *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	logger := log.ContextLogger(ctx)

	cert, err := x509ca.MakeX509(subj)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(subj.PublicKey)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	req, err := Req(c.parent, pubKeyBytes, cert)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	logger.Infof("requesting cert from %s for %v", c.parent, subj.Value)

	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromPEM(subj, resp.PemCertificate, resp.PemCertificateChain)
}
