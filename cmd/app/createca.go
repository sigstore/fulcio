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

package app

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	label = "FulcioCA"
)

func publicKeyFromPrivate(privKey crypto.PrivateKey) (crypto.PublicKey, error) {
	var err error
	switch key := privKey.(type) {
	case *ecdsa.PrivateKey:
		return key.Public().(crypto.PublicKey).(*ecdsa.PublicKey), nil
	case *rsa.PrivateKey:
		return key.Public().(crypto.PublicKey).(*rsa.PublicKey), nil
	default:
		err = errors.New("error generating public key")
	}
	return nil, err
}

// createcaCmd represents the createca command
var createcaCmd = &cobra.Command{
	Use:   "createca",
	Short: "Create a root CA in a pkcs11 device",
	Long: `Create an x509 root CA within a pkcs11 device using values
such as organization, country etc. This can then be used as the root
certificate authority for an instance of sigstore fulcio`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Logger.Info("binding to PKCS11 HSM")
		p11Ctx, err := crypto11.ConfigureFromFile("config/crypto11.conf")
		if err != nil {
			log.Logger.Fatal(err)
		}
		defer p11Ctx.Close()

		rootID := []byte(viper.GetString("hsm-caroot-id"))

		// Check if CA already exists (or a cert within the provided ID)
		findCA, err := p11Ctx.FindCertificate(rootID, nil, nil)
		if err != nil {
			log.Logger.Fatal(err)
		}
		if findCA != nil {
			log.Logger.Fatal("certificate already exists with this ID")
		}

		// Find the existing Key Pair
		// TODO: We could make the TAG customizable
		log.Logger.Info("finding slot for private key: ", label)
		privKey, err := p11Ctx.FindKeyPair(nil, []byte(label))
		if err != nil {
			log.Logger.Fatal(err)
		}

		pubKey, err := publicKeyFromPrivate(privKey)
		if err != nil {
			log.Logger.Fatal(err)
		}

		// Generate a Random Serial Number
		// TODO: We could make it so this could be passed in by the user
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
		if err != nil {
			log.Logger.Fatal(err)
		}
		rootCA := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization:  []string{viper.GetString("org")},
				Country:       []string{viper.GetString("country")},
				Province:      []string{viper.GetString("province")},
				Locality:      []string{viper.GetString("locality")},
				StreetAddress: []string{viper.GetString("street-address")},
				PostalCode:    []string{viper.GetString("postal-code")},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		caBytes, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, pubKey, privKey)
		if err != nil {
			log.Logger.Fatal(err)
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})

		log.Logger.Info("Root CA:")
		fmt.Println(string(pemBytes))

		certParse, err := x509.ParseCertificate(caBytes)
		if err != nil {
			log.Logger.Fatal(err)
		}

		// Import the root CA into the HSM
		// TODO: We could make the TAG customizable
		err = p11Ctx.ImportCertificateWithLabel(rootID, []byte(label), certParse)
		if err != nil {
			log.Logger.Fatal(err)
		}
		log.Logger.Info("root CA created with PKCS11 ID: ", viper.GetString("hsm-caroot-id"))

		// Save out the file in pem format for easy import to CTL chain
		if viper.IsSet("out") {
			certOut, err := os.Create(viper.GetString("out"))
			if err != nil {
				log.Logger.Fatal(err)
			}
			if err := pem.Encode(certOut, &pem.Block{ //nolint
				Type:  "CERTIFICATE",
				Bytes: caBytes},
			); err != nil {
				log.Logger.Fatal(err)
			}
			certOut.Close()
			log.Logger.Info("root CA saved to file: ", viper.GetString("out"))
		}
	},
}

func init() {
	rootCmd.AddCommand(createcaCmd)
	createcaCmd.PersistentFlags().String("org", "Fuclio Root CA", "Organization name for root CA")
	createcaCmd.PersistentFlags().String("country", "", "Country name for root CA")
	createcaCmd.PersistentFlags().String("province", "", "Province name for root CA")
	createcaCmd.PersistentFlags().String("locality", "", "Locality name for root CA")
	createcaCmd.PersistentFlags().String("street-address", "", "Locality name for root CA")
	createcaCmd.PersistentFlags().String("postal-code", "", "Locality name for root CA")
	createcaCmd.PersistentFlags().String("out", "", "output root CA to file")
	if err := viper.BindPFlags(createcaCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err)
	}
}
