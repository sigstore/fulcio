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

	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/protobuf/types/known/durationpb"
)

var (
	pubKeyFile string
	uri        string
	commonName string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a fulcio-signed certificate",
	Long:  `Generate is used to create a fulcio-signed certificate`,
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

	// TODO: we probably want this to be the API endpoint?
	uri := "https://sigstore.dev"
	parent := viper.GetString("gcp_private_ca_parent")

	req := cert(parent, uri, pemBytes)

	resp, err := ca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return errors.Wrap(err, "creating cert")
	}

	// TODO: Add to CTL once there is an exposed IP for it

	fmt.Println(resp.GetPemCertificate())
	return nil
}

func cert(parent, uri string, pemBytes []byte) *privatecapb.CreateCertificateRequest {
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
	generateCmd.PersistentFlags().String("gcp_private_ca_parent", "projects/project-rekor/locations/us-central1/certificateAuthorities/sigstore", "private ca parent: /projects/<project>/locations/<location>/<name>")
	generateCmd.PersistentFlags().StringVar(&pubKeyFile, "public-key-file", "", "path to the PEM encoded public key")
	generateCmd.PersistentFlags().StringVar(&uri, "uri", "", "uri for the cert")
	generateCmd.PersistentFlags().StringVar(&commonName, "common-name", "", "common name for the cert")

	cobra.MarkFlagRequired(generateCmd.Flags(), "public-key-file")

	if err := viper.BindPFlags(generateCmd.PersistentFlags()); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rootCmd.AddCommand(generateCmd)

}
