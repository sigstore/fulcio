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
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/sigstore/fulcio/pkg/ca/fulcioca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/pkcs11"
	"github.com/spf13/viper"
)

func FulcioCASigningCertHandler(subj *challenges.ChallengeResult, publicKey []byte) (string, []string, error) {

	p11Ctx, err := pkcs11.InitHSMCtx()
	if err != nil {
		return "", nil, err
	}
	defer p11Ctx.Close()

	rootID := []byte(viper.GetString("hsm-caroot-id"))

	// get the existing root CA from the HSM
	rootCA, err := p11Ctx.FindCertificate(rootID, nil, nil)
	if err != nil {
		return "", nil, err
	}

	// get the private key object from HSM
	privKey, err := p11Ctx.FindKeyPair(nil, []byte("FulcioCA"))
	if err != nil {
		return "", nil, err
	}

	pkixPubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return "", nil, err
	}

	clientCert, _, err := fulcioca.CreateClientCertificate(rootCA, subj, pkixPubKey, privKey)
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
