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

package x509ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/challenges"
)

func TestGenerateSerialNumber(t *testing.T) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("unexpected error generating serial number: %v", err)
	}
	if serialNumber.Cmp(big.NewInt(0)) == -1 {
		t.Fatalf("serial number is negative: %v", serialNumber)
	}
	if serialNumber.Cmp(big.NewInt(0)) == 0 {
		t.Fatalf("serial number is 0: %v", serialNumber)
	}
	maxSerial := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil)
	// Serial number must be less than max serial number.
	if serialNumber.Cmp(maxSerial) >= 0 {
		t.Fatalf("serial number is too large: %v", serialNumber)
	}
}

func mustNewTestPublicKey() crypto.PublicKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv.Public()
}

func TestMakeCert(t *testing.T) {
	tests := map[string]struct {
		Challenge challenges.ChallengeResult
		WantErr   bool
		WantFacts map[string]func(x509.Certificate) error
	}{
		`Github workflow challenge should have all Github workflow extensions and issuer set`: {
			Challenge: challenges.ChallengeResult{
				Issuer:    `https://token.actions.githubusercontent.com`,
				TypeVal:   challenges.GithubWorkflowValue,
				PublicKey: mustNewTestPublicKey(),
				Value:     `https://github.com/foo/bar/`,
				AdditionalInfo: map[challenges.AdditionalInfo]string{
					challenges.GithubWorkflowSha:        "sha",
					challenges.GithubWorkflowTrigger:    "trigger",
					challenges.GithubWorkflowName:       "workflowname",
					challenges.GithubWorkflowRepository: "repository",
					challenges.GithubWorkflowRef:        "ref",
				},
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certifificate should have correct issuer`:     factIssuerIs(`https://token.actions.githubusercontent.com`),
				`Certificate has correct trigger extension`:    factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, "trigger"),
				`Certificate has correct SHA extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, "sha"),
				`Certificate has correct workflow extension`:   factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, "workflowname"),
				`Certificate has correct repository extension`: factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, "repository"),
				`Certificate has correct ref extension`:        factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, "ref"),
			},
		},
		`Email challenges should set issuer extension and email subject`: {
			Challenge: challenges.ChallengeResult{
				Issuer:    `example.com`,
				TypeVal:   challenges.EmailValue,
				PublicKey: mustNewTestPublicKey(),
				Value:     `alice@example.com`,
			},
			WantErr: false,
			WantFacts: map[string]func(x509.Certificate) error{
				`Certificate should have alice@example.com email subject`: func(cert x509.Certificate) error {
					if len(cert.EmailAddresses) != 1 {
						return errors.New("no email SAN set for email challenge")
					}
					if cert.EmailAddresses[0] != `alice@example.com` {
						return errors.New("bad email. expected alice@example.com")
					}
					return nil
				},
				`Certificate should have issuer extension set`: factIssuerIs("example.com"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert, err := MakeX509(&test.Challenge)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
				return
			}
			for factName, fact := range test.WantFacts {
				t.Run(factName, func(t *testing.T) {
					if err := fact(*cert); err != nil {
						t.Error(err)
					}
				})
			}
		})
	}
}

func factIssuerIs(issuer string) func(x509.Certificate) error {
	return factExtensionIs(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, issuer)
}

func factExtensionIs(oid asn1.ObjectIdentifier, value string) func(x509.Certificate) error {
	return func(cert x509.Certificate) error {
		for _, ext := range cert.ExtraExtensions {
			if ext.Id.Equal(oid) {
				if !bytes.Equal(ext.Value, []byte(value)) {
					return fmt.Errorf("expected oid %v to be %s, but got %s", oid, value, ext.Value)
				}
				return nil
			}
		}
		return errors.New("extension not set")
	}
}
