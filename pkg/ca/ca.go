package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

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

func Check(pub []byte, proof string, email string) bool {
	pkixPub, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return false
	}
	ecPub, ok := pkixPub.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	h := sha256.Sum256([]byte(email))
	sig, err := base64.StdEncoding.DecodeString(proof)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(ecPub, h[:], sig)
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
