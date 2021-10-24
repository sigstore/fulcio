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

package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/ca/pkcs11ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/pkcs11"
	"github.com/spf13/viper"
)

func Pkcs11CASigningCertHandler(ctx context.Context, principal *oidc.IDToken, subj *challenges.ChallengeResult, publicKey []byte) (string, []string, error) {
	logger := log.ContextLogger(ctx)

	p11Ctx, err := pkcs11.InitHSMCtx()
	if err != nil {
		return "", nil, err
	}
	defer p11Ctx.Close()

	rootID := []byte(viper.GetString("hsm-caroot-id"))

	// get the existing root CA from the HSM or from disk
	var rootCA *x509.Certificate
	if !viper.IsSet("aws-hsm-root-ca-path") {
		rootCA, err = p11Ctx.FindCertificate(rootID, nil, nil)
		if err != nil {
			return "", nil, err
		}
	} else {
		rootCaPath := filepath.Clean(viper.GetString("aws-hsm-root-ca-path"))
		pubPEMData, err := os.ReadFile(rootCaPath)
		if err != nil {
			return "", nil, err
		}
		block, _ := pem.Decode(pubPEMData)
		if block == nil || block.Type != "CERTIFICATE" {
			logger.Fatal("failed to decode PEM block containing certificate")
		}
		rootCA, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", nil, err
		}
	}

	// get the private key object from HSM
	privKey, err := p11Ctx.FindKeyPair(nil, []byte("PKCS11CA"))
	if err != nil {
		return "", nil, err
	}

	pkixPubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return "", nil, err
	}

	clientCert, _, err := pkcs11ca.CreateClientCertificate(rootCA, principal, subj, pkixPubKey, privKey)
	if err != nil {
		return "", nil, err
	}

	// Format in PEM
	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCA.Raw,
	})

	return clientCert, []string{string(rootPEM)}, nil
}
