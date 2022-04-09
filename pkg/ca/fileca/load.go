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

package fileca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"

	"github.com/sigstore/fulcio/pkg/ca/intermediateca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"go.step.sm/crypto/pemutil"
)

func loadKeyPair(certPath, keyPath, keyPass string) ([]*x509.Certificate, crypto.Signer, error) {
	var (
		certs []*x509.Certificate
		err   error
		key   crypto.Signer
	)

	data, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, nil, err
	}
	certs, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}

	{
		opaqueKey, err := pemutil.Read(keyPath, pemutil.WithPassword([]byte(keyPass)))
		if err != nil {
			return nil, nil, err
		}

		var ok bool
		key, ok = opaqueKey.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New(`fileca: loaded private key can't be used to sign`)
		}
	}

	if err := intermediateca.VerifyCertChain(certs, key); err != nil {
		return nil, nil, err
	}

	return certs, key, nil
}
