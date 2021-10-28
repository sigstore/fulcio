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

package googlecabeta

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/viper"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	once sync.Once
	c    *privateca.CertificateAuthorityClient
)

type CertAuthorityService struct {
	parent string
	client *privateca.CertificateAuthorityClient
}

func NewCertAuthorityService() (*CertAuthorityService, error) {
	cas := &CertAuthorityService{
		parent: viper.GetString("gcp_private_ca_parent"),
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
	var err error
	once.Do(func() {
		c, err = privateca.NewCertificateAuthorityClient(context.Background())
	})

	return c, err
}

// Returns the PublicKey type required by gcp privateca (to handle both PEM_RSA_KEY / PEM_EC_KEY)
// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#PublicKey_KeyType
func getPubKeyType(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return privatecapb.PublicKey_KeyType(1), nil
	case *ecdsa.PublicKey:
		return privatecapb.PublicKey_KeyType(2), nil
	default:
		return nil, fmt.Errorf("unknown public key type: %v", pub)
	}
}

func Req(parent string, subject *privatecapb.CertificateConfig_SubjectConfig, pemBytes []byte, extensions []*privatecapb.X509Extension) (*privatecapb.CreateCertificateRequest, error) {
	// TODO, use the right fields :)
	pubkeyType, err := getPubKeyType(pemBytes)
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
	}

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(subj.PublicKey)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	extensions := IssuerExtension(subj.Issuer)

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
