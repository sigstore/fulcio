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

package ephemeralca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/sigstore/pkg/signature"
)

type EphemeralCA struct {
	x509ca.X509CA
}

func NewEphemeralCA() (*EphemeralCA, error) {
	e := &EphemeralCA{}
	var err error

	signer, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		return nil, err
	}

	e.PrivKey = signer

	serialNumber, err := x509ca.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	rootCA := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"sigstore"},
			Country:       []string{"USA"},
			Province:      []string{"WA"},
			Locality:      []string{"Kirkland"},
			StreetAddress: []string{"767 6th St S"},
			PostalCode:    []string{"98033"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, MaxPathLen: 1,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	e.RootCA, err = x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	return e, nil
}
