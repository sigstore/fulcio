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
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
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
	pemBytes, err := ioutil.ReadFile(filepath.Clean(pubKeyFile))
	if err != nil {
		return errors.Wrap(err, "reading pub key file")
	}
	parent := viper.GetString("gcp-private-ca-parent")
	timestamping := viper.GetBool("timestamping")
	req := cert(parent, uri, pemBytes, timestamping)
	fmt.Println(req.String())
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return errors.Wrap(err, "creating ca client")
	}
	resp, err := client.CreateCertificate(ctx, req)
	if err != nil {
		return errors.Wrap(err, "creating cert")
	}
	fmt.Println(resp.GetConfig().String())
	fmt.Println(resp.CertificateDescription.String())

	// print cert and cert chain to STDOUT
	fmt.Println(resp.GetPemCertificate())
	fmt.Println("")
	fmt.Println(resp.GetPemCertificateChain())
	return nil
}

func cert(parent, uri string, pemBytes []byte, _ bool) *privatecapb.CreateCertificateRequest {
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil
	}
	additionalExtensions := []*privatecapb.X509Extension{{
		ObjectId: &privatecapb.ObjectId{ObjectIdPath: []int32{2, 5, 29, 37}},
		Critical: true,
		Value:    timestampExt,
	}}

	// AdditionalExtensions: additionalExtensions,

	// TODO, use the right fields :)
	isCa := true
	maxPathLen := int32(0)
	return &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			// should be 6 months
			Lifetime: &durationpb.Duration{Seconds: int64(15780000)},
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    pemBytes,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								ContentCommitment: true,
								CertSign:          true,
							},
							/*
								ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
									TimeStamping: true,
								},
							*/
						},
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa:                &isCa,
							MaxIssuerPathLength: &maxPathLen,
						},
						AdditionalExtensions: additionalExtensions,
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							Organization: uri,
						},
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
	generateCmd.PersistentFlags().Bool("timestamping", false, "Configure certificate for timestamping")

	if err := viper.BindPFlags(generateCmd.PersistentFlags()); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rootCmd.AddCommand(generateCmd)
}
