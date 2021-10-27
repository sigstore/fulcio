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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"time"
)

var (
	ca      *x509.Certificate
	privKey interface{}
)

func Initialize(context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	privKey = priv

	// TODO: We could make it so this could be passed in by the user
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return err
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

	caBytes, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, priv.Public(), priv)
	if err != nil {
		return err
	}

	ca, err = x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}

	return nil
}

func CA() (*x509.Certificate, interface{}) {
	return ca, privKey
}
