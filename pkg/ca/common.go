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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func MakeX509(ctx context.Context, principal identity.Principal, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	serialNumber, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	skid, err := cryptoutils.SKID(publicKey)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * 10),
		SubjectKeyId: skid,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	err = principal.Embed(ctx, cert)
	if err != nil {
		return nil, ValidationError(err)
	}

	return cert, nil
}
