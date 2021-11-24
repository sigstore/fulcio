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

package x509ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/sigstore/fulcio/pkg/pkcs11"
	"github.com/spf13/viper"
)

func NewX509CA() (*X509CA, error) {
	ca := &X509CA{}
	p11Ctx, err := pkcs11.InitHSMCtx()
	if err != nil {
		return nil, err
	}
	defer p11Ctx.Close()

	rootID := []byte(viper.GetString("hsm-caroot-id"))

	// get the existing root CA from the HSM or from disk
	if !viper.IsSet("aws-hsm-root-ca-path") {
		ca.RootCA, err = p11Ctx.FindCertificate(rootID, nil, nil)
		if err != nil {
			return nil, err
		}
	} else {
		rootCaPath := filepath.Clean(viper.GetString("aws-hsm-root-ca-path"))
		pubPEMData, err := os.ReadFile(rootCaPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pubPEMData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("failed to decode PEM block containing certificate")
		}
		ca.RootCA, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// get the private key object from HSM
	ca.PrivKey, err = p11Ctx.FindKeyPair(nil, []byte("PKCS11CA"))
	if err != nil {
		return nil, err
	}

	return ca, nil

}
