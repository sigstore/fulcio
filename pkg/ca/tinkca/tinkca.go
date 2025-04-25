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

package tinkca

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/baseca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	tinkUtils "github.com/sigstore/sigstore/pkg/signature/tink"
	"github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type tinkCA struct {
	baseca.BaseCA
}

// NewTinkCA creates a signer from an encrypted Tink keyset, encrypted with a GCP KMS key.
func NewTinkCA(ctx context.Context, kmsKey, tinkKeysetPath, certPath string) (ca.CertificateAuthority, error) {
	primaryKey, err := GetPrimaryKey(ctx, kmsKey)
	if err != nil {
		return nil, err
	}

	return NewTinkCAFromHandle(ctx, tinkKeysetPath, certPath, primaryKey)
}

// NewTinkCAFromHandle creates a signer from an encrypted Tink keyset, encrypted with an AEAD key.
func NewTinkCAFromHandle(_ context.Context, tinkKeysetPath, certPath string, primaryKey tink.AEAD) (ca.CertificateAuthority, error) {
	var tca tinkCA

	f, err := os.Open(filepath.Clean(tinkKeysetPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kh, err := keyset.Read(keyset.NewJSONReader(f), primaryKey)
	if err != nil {
		return nil, err
	}
	signer, err := tinkUtils.KeyHandleToSigner(kh)
	if err != nil {
		return nil, err
	}

	sc := ca.SignerCerts{}
	tca.SignerWithChain = &sc

	sc.Signer = signer

	data, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, err
	}
	sc.Certs, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if err := ca.VerifyCertChain(sc.Certs, sc.Signer); err != nil {
		return nil, err
	}

	return &tca, nil
}

// GetPrimaryKey returns a Tink AEAD encryption key from KMS
// Supports GCP and AWS
func GetPrimaryKey(ctx context.Context, kmsKey string) (tink.AEAD, error) {
	switch {
	case strings.HasPrefix(kmsKey, "gcp-kms://"):
		gcpClient, err := gcpkms.NewClientWithOptions(ctx, kmsKey)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(gcpClient)
		return gcpClient.GetAEAD(kmsKey)
	case strings.HasPrefix(kmsKey, "aws-kms://"):
		awsClient, err := awskms.NewClientWithOptions(kmsKey)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(awsClient)
		return awsClient.GetAEAD(kmsKey)
	default:
		return nil, errors.New("unsupported KMS key type")
	}
}
