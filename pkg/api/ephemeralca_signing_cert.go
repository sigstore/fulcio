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

	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/challenges"
)

func EphemeralCASigningCertHandler(ctx context.Context, subj *challenges.ChallengeResult, publicKey []byte) (string, []string, error) {
	rootCA, privKey := ephemeralca.CA()

	pkixPubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return "", nil, err
	}

	clientCert, _, err := x509ca.CreateClientCertificate(rootCA, subj, pkixPubKey, privKey)
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
