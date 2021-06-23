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
	"encoding/pem"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"math/big"
	"net/url"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/google/uuid"
)

func CreateClientCertificate(rootCA *x509.Certificate, subject challenges.ChallengeResult, publicKeyPEM interface{}, privKey crypto11.Signer) (string, []string,  error) {
	// TODO: Track / increment serial nums instead, although unlikely we will create dupes, it could happen
	uuid := uuid.New()
	var serialNumber big.Int
	serialNumber.SetBytes(uuid[:])
	//email := []string{subject}
	cert := &x509.Certificate{
		SerialNumber:   &serialNumber,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Minute * 10),
		SubjectKeyId:   []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:       x509.KeyUsageCertSign,
	}
	switch subject.TypeVal {
	case challenges.EmailValue:
		cert.EmailAddresses = []string{subject.Value}
	case challenges.SpiffeValue:
		challengeUrl, err:= url.Parse(subject.Value)
		if err != nil {
			return "", nil, err
		}
	   cert.URIs = []*url.URL{challengeUrl}
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, rootCA, publicKeyPEM, privKey)
	if err != nil {
		return "", nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	log.Logger.Info("certPEM:", string(certPEM))

	return string(certPEM), nil, nil
}
