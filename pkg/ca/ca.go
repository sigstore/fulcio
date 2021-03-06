package ca

import (
	"context"

	"github.com/spf13/viper"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var Client *privateca.CertificateAuthorityClient

func init() {
	c, err := privateca.NewCertificateAuthorityClient(context.Background())
	if err != nil {
		panic(err)
	}
	Client = c
}

func Req(email string, pemBytes []byte) *privatecapb.CreateCertificateRequest {
	parent := viper.GetString("gcp_private_ca_parent")
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
