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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/sigstore/fulcio/pkg/oauthflow"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/generated/client"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"golang.org/x/oauth2"

	"github.com/spf13/cobra"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
)

var (
	fulcioAddr string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fulcio-client",
	Short: "Fulcio",
	Long:  "Fulcio generates certificates that can be used to sign software artifacts",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, err := oidc.NewProvider(context.Background(), viper.GetString("oidc-issuer"))
		if err != nil {
			return err
		}

		config := oauth2.Config{
			ClientID:     viper.GetString("oidc-client-id"),
			ClientSecret: viper.GetString("oidc-client-secret"),
			Endpoint:     provider.Endpoint(),
			RedirectURL:  "http://localhost:5556/auth/callback",
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		}
		idToken, err := oauthflow.GetIDToken(provider, config)
		if err != nil {
			return err
		}

		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.ParsedToken.Claims(&claims); err != nil {
			return err
		}
		if !claims.Verified {
			return errors.New("email not verified by identity provider")
		}

		fmt.Println(claims.Email)
		// Generate key pair
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		if err != nil {
			return err
		}
		pubBytesB64 := strfmt.Base64(pubBytes)
		// Sign the email address as part of the request
		h := sha256.Sum256([]byte(claims.Email))
		proof, err := ecdsa.SignASN1(rand.Reader, pk, h[:])
		if err != nil {
			return err
		}
		proofB64 := strfmt.Base64(proof)
		fcli, err := GetFulcioClient(fulcioAddr)
		if err != nil {
			return err
		}

		bearerAuth := httptransport.BearerToken(idToken.RawString)

		params := operations.NewSigningCertParams()
		params.SetCertificateRequest(&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Content:   &pubBytesB64,
				Algorithm: swag.String(models.CertificateRequestPublicKeyAlgorithmEcdsa),
			},
			SignedEmailAddress: &proofB64,
		})
		resp, err := fcli.Operations.SigningCert(params, bearerAuth)
		if err != nil {
			return err
		}

		outputFileStr := viper.GetString("output")
		outputFile := os.Stdout
		if outputFileStr != "-" {
			var err error
			outputFile, err = os.Create(filepath.Clean(outputFileStr))
			if err != nil {
				log.Fatal(err)
			}
			defer func() {
				if err := outputFile.Close(); err != nil {
					fmt.Fprint(os.Stderr, err)
				}
			}()
		}
		fmt.Fprint(outputFile, resp.Payload)

		return nil
	},
}

func GetFulcioClient(addr string) (*client.Fulcio, error) {
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	rt := httptransport.New(url.Host, client.DefaultBasePath, []string{url.Scheme})
	rt.Consumers["application/pem-certificate-chain"] = runtime.TextConsumer()
	return client.New(rt, strfmt.Default), nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {

	rootCmd.PersistentFlags().StringVar(&fulcioAddr, "fulcio_address", "http://127.0.0.1:5555", "address of fulcio server")
	rootCmd.PersistentFlags().String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "OIDC provider to be used to issue ID token")
	rootCmd.PersistentFlags().String("oidc-client-id", "sigstore", "client ID for application")
	rootCmd.PersistentFlags().String("oidc-client-secret", "", "client secret for application")
	rootCmd.PersistentFlags().StringP("output", "o", "-", "output file to write certificate chain to")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Println(err)
	}
}
