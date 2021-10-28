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

package googleca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func Req(parent string, subject *privatecapb.CertificateConfig_SubjectConfig, pemBytes []byte, extensions []*privatecapb.X509Extension) *privatecapb.CreateCertificateRequest {
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
								AdditionalExtensions: extensions,
							},
						},
					},
					SubjectConfig: subject,
				},
			},
		},
	}
}

func EmailSubject(email string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			EmailAddresses: []string{email},
		}}
}

// SPIFFE IDs go as "Uris" according to the spec: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
func SpiffeSubject(id string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			Uris: []string{id},
		},
	}
}

func GithubWorkflowSubject(id string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			Uris: []string{id},
		},
	}
}

func KubernetesSubject(id string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			Uris: []string{id},
		},
	}
}

func IssuerExtension(issuer string) []*privatecapb.X509Extension {
	if issuer == "" {
		return nil
	}

	return []*privatecapb.X509Extension{{
		ObjectId: &privatecapb.ObjectId{
			ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 57264, 1, 1},
		},
		Value: []byte(issuer),
	}}
}
