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
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	fulcioUrl    = "https://fulcio.sigstore.dev"
	oidcIssuer   = "https://oauth2.sigstore.dev/auth"
	oidcClientID = "sigstore"
)

// Some of this is just ripped from cosign
func GetCert(signer *signature.RSAPKCS1v15SignerVerifier, fc fulciopb.CAClient, oidcIssuer string, oidcClientID string) (*fulciopb.SigningCertificate, error) {

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

	pubBytesPEM, err := cryptoutils.MarshalPublicKeyToPEM(signer.Public())
	if err != nil {
		return nil, err
	}
	cscr := &fulciopb.CreateSigningCertificateRequest{
		Credentials: &fulciopb.Credentials{
			Credentials: &fulciopb.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok.RawString,
			},
		},
		PublicKey: &fulciopb.PublicKey{
			Content: string(pubBytesPEM),
		},
		ProofOfPossession: proof,
	}
	return fc.CreateSigningCertificate(context.Background(), cscr)
}

func NewClient(fulcioURL string) (fulciopb.CAClient, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	dialOpt := grpc.WithTransportCredentials(insecure.NewCredentials())
	if fulcioServer.Scheme == "https" {
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}
	conn, err := grpc.Dial(fulcioServer.Host, dialOpt)
	if err != nil {
		return nil, err
	}
	return fulciopb.NewCAClient(conn), nil
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

	var chain *fulciopb.CertificateChain
	switch cert := certResp.Certificate.(type) {
	case *fulciopb.SigningCertificate_SignedCertificateDetachedSct:
		chain = cert.SignedCertificateDetachedSct.GetChain()
	case *fulciopb.SigningCertificate_SignedCertificateEmbeddedSct:
		chain = cert.SignedCertificateEmbeddedSct.GetChain()
	}
	clientPEM, _ := pem.Decode([]byte(chain.Certificates[0]))
	cert, err := x509.ParseCertificate(clientPEM.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received signing cerificate with serial number: ", cert.SerialNumber)
}
