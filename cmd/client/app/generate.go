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

package app

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sigstore/fulcio/pkg/log"

	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	pubKeyFile string
	uri        string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a fulcio-signed certificate",
	Long:  `Generate is used to create a fulcio-signed certificate without OIDC`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateCert(context.Background()); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func generateCert(ctx context.Context) error {
	pemBytes, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		return errors.Wrap(err, "reading pub key file")
	}
	parent := viper.GetString("gcp-private-ca-parent")
	req := cert(parent, uri, pemBytes)
	resp, err := ca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return errors.Wrap(err, "creating cert")
	}

	// Submit to CTL
	log.Logger.Info("Submitting cert to CT log")
	ctURL := viper.GetString("ct-log-url")
	c := ctl.New(ctURL)
	ct, err := c.AddChain(resp.PemCertificate, resp.PemCertificateChain)
	if err != nil {
		return errors.Wrap(err, "add chain")
	}
	log.Logger.Info("CTL Submission Signature Received: ", ct.Signature)
	log.Logger.Info("CTL Submission ID Received: ", ct.ID)

	// print cert and cert chain to STDOUT
	fmt.Println(resp.GetPemCertificate())
	fmt.Println("")
	fmt.Println(resp.GetPemCertificateChain())
	return nil
}

func cert(parent, uri string, pemBytes []byte) *privatecapb.CreateCertificateRequest {
	// TODO, use the right fields :)
	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			// should be 6 months
			Lifetime: &durationpb.Duration{Seconds: int64(15780000)},
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
						SubjectAltName: &privatecapb.SubjectAltNames{
							Uris: []string{uri},
						},
					},
				},
			},
		},
	}
}

func init() {
	generateCmd.PersistentFlags().String("gcp-private-ca-parent", "projects/project-rekor/locations/us-central1/certificateAuthorities/sigstore", "private ca parent: /projects/<project>/locations/<location>/<name>")
	generateCmd.PersistentFlags().StringVar(&pubKeyFile, "public-key-file", "", "path to the PEM encoded public key")
	generateCmd.PersistentFlags().StringVar(&uri, "uri", "", "uri for the cert")
	generateCmd.PersistentFlags().String("ct-log-url", "", "host and path (with log prefix at the end) to the ct log")

	if err := viper.BindPFlags(generateCmd.PersistentFlags()); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rootCmd.AddCommand(generateCmd)
}
