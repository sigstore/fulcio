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
	"encoding/pem"
	"fmt"
	"sync"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	once sync.Once
	c    *privateca.CertificateAuthorityClient
	cErr error
)

type CertAuthorityService struct {
	parent string
	client *privateca.CertificateAuthorityClient
}

func NewCertAuthorityService(parent string) (*CertAuthorityService, error) {
	cas := &CertAuthorityService{
		parent: parent,
	}
	var err error
	cas.client, err = casClient()
	if err != nil {
		return nil, err
	}
	return cas, nil
}

func casClient() (*privateca.CertificateAuthorityClient, error) {
	// Use a once block to avoid creating a new client every time.
	once.Do(func() {
		c, cErr = privateca.NewCertificateAuthorityClient(context.Background())
	})

	return c, cErr
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

func Req(parent string, subject *privatecapb.CertificateConfig_SubjectConfig, pemBytes []byte, extensions []*privatecapb.X509Extension) (*privatecapb.CreateCertificateRequest, error) {
	// TODO, use the right fields :)
	pubkeyFormat, err := getPubKeyFormat(pemBytes)
	if err != nil {
		return nil, err
	}
	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			Lifetime: &durationpb.Duration{Seconds: 20 * 60},
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

func emailSubject(email string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			EmailAddresses: []string{email},
		}}
}

// SPIFFE IDs go as "Uris" according to the spec: https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
func spiffeSubject(id string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			Uris: []string{id},
		},
	}
}

func githubWorkflowSubject(id string) *privatecapb.CertificateConfig_SubjectConfig {
	return &privatecapb.CertificateConfig_SubjectConfig{
		SubjectAltName: &privatecapb.SubjectAltNames{
			Uris: []string{id},
		},
	}
}

func AdditionalExtensions(subject *challenges.ChallengeResult) []*privatecapb.X509Extension {
	res := []*privatecapb.X509Extension{}
	if subject.TypeVal == challenges.GithubWorkflowValue {
		if trigger, ok := subject.AdditionalInfo[challenges.GithubWorkflowTrigger]; ok {
			res = append(res, &privatecapb.X509Extension{
				ObjectId: &privatecapb.ObjectId{
					ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 57264, 1, 3},
				},
				Value: []byte(trigger),
			})
		}

		if sha, ok := subject.AdditionalInfo[challenges.GithubWorkflowSha]; ok {
			res = append(res, &privatecapb.X509Extension{
				ObjectId: &privatecapb.ObjectId{
					ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 57264, 1, 2},
				},
				Value: []byte(sha),
			})
		}
	}
	return res
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

func (c *CertAuthorityService) CreateCertificate(ctx context.Context, subj *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	logger := log.ContextLogger(ctx)
	var privca *privatecapb.CertificateConfig_SubjectConfig
	switch subj.TypeVal {
	case challenges.EmailValue:
		privca = emailSubject(subj.Value)
	case challenges.SpiffeValue:
		privca = spiffeSubject(subj.Value)
	case challenges.GithubWorkflowValue:
		privca = githubWorkflowSubject(subj.Value)
	case challenges.KubernetesValue:
		privca = KubernetesSubject(subj.Value)
	}

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(subj.PublicKey)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	extensions := append(IssuerExtension(subj.Issuer), AdditionalExtensions(subj)...)

	req, err := Req(c.parent, privca, pubKeyBytes, extensions)
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
