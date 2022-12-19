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

package pkcs11ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/ThalesIgnite/crypto11"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/baseca"
)

type Params struct {
	ConfigPath string
	RootID     string
	CAPath     *string
}

type PKCS11CA struct {
	baseca.BaseCA
}

func NewPKCS11CA(params Params) (*PKCS11CA, error) {
	pkcs11ca := &PKCS11CA{}
	p11Ctx, err := crypto11.ConfigureFromFile(params.ConfigPath)
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate

	rootID := []byte(params.RootID)

	// get the existing root CA from the HSM or from disk
	if params.CAPath == nil {
		cert, err = p11Ctx.FindCertificate(rootID, nil, nil)
		if err != nil {
			return nil, err
		}
	} else {
		rootCaPath := filepath.Clean(*params.CAPath)
		pubPEMData, err := os.ReadFile(rootCaPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pubPEMData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("failed to decode PEM block containing certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// get the private key object from HSM
	signer, err := p11Ctx.FindKeyPair(nil, []byte("PKCS11CA"))
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("cannot find private key")
	}

	sc := ca.SignerCerts{Signer: signer, Certs: []*x509.Certificate{cert}}
	pkcs11ca.SignerWithChain = &sc

	return pkcs11ca, nil

}
