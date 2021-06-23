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

package fulcioca

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/google/uuid"
)

func CreateClientCertificate(rootCA *x509.Certificate, emailAddress string, publicKeyPEM interface{}, privKey crypto11.Signer) ([]byte, error) {
	// TODO: Track / increment serial nums instead, although unlikely we will create dupes, it could happen
	uuid := uuid.New()
	var serialNumber big.Int
	serialNumber.SetBytes(uuid[:])
	email := []string{emailAddress}
	cert := &x509.Certificate{
		SerialNumber:   &serialNumber,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Minute * 10),
		SubjectKeyId:   []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:       x509.KeyUsageCertSign,
		EmailAddresses: email,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, rootCA, publicKeyPEM, privKey)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}
