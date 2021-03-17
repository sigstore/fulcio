/*
Copyright © 2021 Dan Lorenc <lorenc.d@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/sigstore/fulcio/pkg/generated/models"
	
	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var once sync.Once
var c *privateca.CertificateAuthorityClient

func Client() *privateca.CertificateAuthorityClient {

	// Use a once block to avoid creating a new client every time.
	once.Do(func() {
		var err error
		c, err = privateca.NewCertificateAuthorityClient(context.Background())
		if err != nil {
			panic(err)
		}
	})
	return c
}

func CheckSignature(alg string, pub crypto.PublicKey, proof []byte, email string) error {
	h := sha256.Sum256([]byte(email))

	switch alg {
	case models.CertificateRequestPublicKeyAlgorithmEcdsa:
		if ok := ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], proof); !ok {
			return errors.New("signature could not be verified")
		}
	}
	return nil
}

func Req(parent, email string, pemBytes []byte) *privatecapb.CreateCertificateRequest {
	// TODO, use the right fields :)
	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			Lifetime: &durationpb.Duration{Seconds: 20 * 60},
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Type: privatecapb.PublicKey_PEM_EC_KEY,
						Key:  pemBytes,
					},
					ReusableConfig: &privatecapb.ReusableConfigWrapper{
						ConfigValues: &privatecapb.ReusableConfigWrapper_ReusableConfigValues{
							ReusableConfigValues: &privatecapb.ReusableConfigValues{
								KeyUsage: &privatecapb.KeyUsage{
									BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
										DigitalSignature: true,
									},
									ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
										CodeSigning: true,
									},
								},
							},
						},
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						CommonName: email,
						SubjectAltName: &privatecapb.SubjectAltNames{
							EmailAddresses: []string{email},
						},
						Subject: &privatecapb.Subject{
							Organization: email,
						},
					},
				},
			},
		},
	}
}
