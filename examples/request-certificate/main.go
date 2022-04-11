// Copyright 2022 The Sigstore Authors.
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

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"

	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	fulcioUrl    = "https://fulcio.sigstore.dev"
	oidcIssuer   = "https://oauth2.sigstore.dev/auth"
	oidcClientID = "sigstore"
)

// Some of this is just ripped from cosign
func GetCert(signer *signature.RSAPKCS1v15SignerVerifier, fc api.Client, oidcIssuer string, oidcClientID string) (*api.CertificateResponse, error) {

	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	b := bytes.NewBuffer([]byte(tok.Subject))
	proof, err := signer.SignMessage(b, options.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		log.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: "rsa4096",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}
	return fc.SigningCert(cr, tok.RawString)
}

func NewClient(fulcioURL string) (api.Client, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	fClient := api.NewClient(fulcioServer, api.WithUserAgent("Fulcio Example Code"))
	return fClient, nil
}

func main() {
	signer, _, err := signature.NewDefaultRSAPKCS1v15SignerVerifier()
	if err != nil {
		log.Fatal(err)
	}

	fClient, err := NewClient(fulcioUrl)
	if err != nil {
		log.Fatal(err)
	}

	certResp, err := GetCert(signer, fClient, oidcIssuer, oidcClientID)
	if err != nil {
		log.Fatal(err)
	}

	clientPEM, _ := pem.Decode([]byte(certResp.CertPEM))
	cert, err := x509.ParseCertificate(clientPEM.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received signing cerificate with serial number: ", cert.SerialNumber)
}
