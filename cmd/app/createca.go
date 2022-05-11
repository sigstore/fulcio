//go:build cgo
// +build cgo

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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	LABEL = "PKCS11CA"
)

func newCreateCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "createca",
		Short: "Create a root CA in a pkcs11 device",
		Long: `Create an x509 root CA within a pkcs11 device using values
such as organization, country etc. This can then be used as the root
certificate authority for an instance of sigstore fulcio`,
		Run: runCreateCACmd,
	}

	cmd.Flags().String("org", "Fulcio Root CA", "Organization name for root CA")
	cmd.Flags().String("country", "", "Country name for root CA")
	cmd.Flags().String("province", "", "Province name for root CA")
	cmd.Flags().String("locality", "", "Locality name for root CA")
	cmd.Flags().String("street-address", "", "Street address for root CA")
	cmd.Flags().String("postal-code", "", "Postal code for root CA")
	cmd.Flags().String("out", "", "output root CA to file")
	cmd.Flags().String("hsm", "softhsm", "The HSM provider to use. Valid values: softhsm (default), aws")
	cmd.Flags().String("pkcs11-config-path", "config/crypto11.conf", "path to fulcio pkcs11 config file")
	cmd.Flags().String("hsm-caroot-id", "", "HSM ID for Root CA")

	err := cmd.MarkFlagRequired("hsm-caroot-id")
	if err != nil {
		log.Logger.Fatal(`Failed to mark flag as required`)
	}

	return cmd
}

func runCreateCACmd(cmd *cobra.Command, args []string) {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		log.Logger.Fatal(err)
	}

	log.Logger.Info("binding to PKCS11 HSM")
	p11Ctx, err := crypto11.ConfigureFromFile(viper.GetString("pkcs11-config-path"))
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
	log.Logger.Infof("finding slot for private key label %q", LABEL)
	privKey, err := p11Ctx.FindKeyPair(nil, []byte(LABEL))
	if err != nil {
		log.Logger.Fatal(err)
	}

	if privKey == nil {
		log.Logger.Fatalf("no key pair was found matching label %q", LABEL)
	}

	pubKey := privKey.Public()

	serialNumber, err := cryptoutils.GenerateSerialNumber()
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, MaxPathLen: 1,
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
	if viper.GetString("hsm") == "aws" {
		log.Logger.Info("Running in AWS mode; skipping root CA storage in HSM")
		if !viper.IsSet("out") {
			log.Logger.Warn("WARNING: --out is not set. Root CA will not be saved.")
		}
	} else {
		if err = p11Ctx.ImportCertificateWithLabel(rootID, []byte(LABEL), certParse); err != nil {
			log.Logger.Fatal(err)
		}
		log.Logger.Info("root CA created with PKCS11 ID: ", viper.GetString("hsm-caroot-id"))
	}

	// Save out the file in pem format for easy import to CTL chain
	if viper.IsSet("out") {
		certOut, err := os.Create(filepath.Clean(viper.GetString("out")))
		if err != nil {
			log.Logger.Fatal(err)
		}
		if err := pem.Encode(certOut, &pem.Block{ //nolint
			Type:  "CERTIFICATE",
			Bytes: caBytes},
		); err != nil {
			certOut.Close()
			log.Logger.Fatal(err)
		}
		certOut.Close()
		log.Logger.Info("root CA saved to file: ", viper.GetString("out"))
	}
}
