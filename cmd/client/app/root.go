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
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/sigstore/fulcio/pkg/oauthflow"

	"github.com/coreos/go-oidc"
	"github.com/sigstore/fulcio/pkg/generated/client"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"golang.org/x/oauth2"

	"github.com/spf13/cobra"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
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
		ctx := context.Background()
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		if err != nil {
			return err
		}
		provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
		if err != nil {
			return err
		}

		config := oauth2.Config{
			ClientID: "237800849078-rmntmr1b2tcu20kpid66q5dbh1vdt7aj.apps.googleusercontent.com",
			// THIS IS NOT A SECRET - IT IS USED IN THE NATIVE/DESKTOP FLOW.
			ClientSecret: "CkkuDoCgE2D_CCRRMyF_UIhS",
			Endpoint:     provider.Endpoint(),
			RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		}
		tok, err := oauthflow.GetAccessToken(provider, config)
		if err != nil {
			return err
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: tok,
		}))
		if err != nil {
			return nil
		}

		fmt.Println(userInfo.Email)
		// Sign the email address as part of the request
		h := sha256.Sum256([]byte(userInfo.Email))
		proof, err := ecdsa.SignASN1(rand.Reader, pk, h[:])
		if err != nil {
			return err
		}
		fcli, err := GetFulcioClient(fulcioAddr)
		if err != nil {
			return err
		}

		apiKeyQueryAuth := httptransport.APIKeyAuth("X-Access-Token", "header", tok)

		params := operations.NewSigningCertParams()
		params.SetSubmitcsr(&models.Submit{
			Pub:   strfmt.Base64(base64.StdEncoding.EncodeToString(pubBytes)),
			Proof: strfmt.Base64(base64.StdEncoding.EncodeToString(proof)),
		})
		resp, err := fcli.Operations.SigningCert(params, apiKeyQueryAuth)
		if err != nil {
			return err
		}
		fmt.Println(resp.Payload.Certificate)

		return nil
	},
}

func GetFulcioClient(addr string) (*client.Fulcio, error) {
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	rt := httptransport.New(url.Host, client.DefaultBasePath, []string{url.Scheme})
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
	rootCmd.PersistentFlags().StringVar(&fulcioAddr, "fulcio_address", "http://localhost:5555	", "address of fulcio server")

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Println(err)
	}
}
