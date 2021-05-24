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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	once sync.Once
	c    *privateca.CertificateAuthorityClient
)

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

func CheckSignature(pub crypto.PublicKey, proof []byte, email string) error {
	h := sha256.Sum256([]byte(email))

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ok := ecdsa.VerifyASN1(k, h[:], proof); !ok {
			return errors.New("signature could not be verified")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], proof); err != nil {
			return fmt.Errorf("signature could not be verified: %v", err)
		}
	}

	return nil
}

// Returns the PublicKey type required by gcp privateca (to handle both PEM_RSA_KEY / PEM_EC_KEY)
// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#PublicKey_KeyType
func getPubKeyType(pemBytes []byte) interface{} {
	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse public key: " + err.Error())
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return privatecapb.PublicKey_KeyType(1)
	case *ecdsa.PublicKey:
		return privatecapb.PublicKey_KeyType(2)
	default:
		panic(fmt.Errorf("unknown public key type: %v", pub))
	}
}

func Req(parent, email string, pemBytes []byte) *privatecapb.CreateCertificateRequest {
	// TODO, use the right fields :)
	pubkeyType := getPubKeyType(pemBytes)
	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			Lifetime: &durationpb.Duration{Seconds: 20 * 60},
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Type: pubkeyType.(privatecapb.PublicKey_KeyType),
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
						SubjectAltName: &privatecapb.SubjectAltNames{
							EmailAddresses: []string{email},
						},
					},
				},
			},
		},
	}
}
