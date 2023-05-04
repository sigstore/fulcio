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

package kmsca

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/baseca"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"

	// Register the provider-specific plugins
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

type kmsCA struct {
	baseca.BaseCA
}

func NewKMSCA(ctx context.Context, kmsKey string, certs []*x509.Certificate, hashFunc crypto.Hash, opts ...signature.RPCOption) (ca.CertificateAuthority, error) {
	var ica kmsCA

	kmsSigner, err := kms.Get(ctx, kmsKey, hashFunc, opts...)
	if err != nil {
		return nil, err
	}
	signer, _, err := kmsSigner.CryptoSigner(ctx, func(err error) {})
	if err != nil {
		return nil, err
	}

	sc := ca.SignerCerts{}
	ica.SignerWithChain = &sc

	sc.Signer = signer
	sc.Certs = certs
	if err := ca.VerifyCertChain(sc.Certs, sc.Signer); err != nil {
		return nil, err
	}

	return &ica, nil
}
