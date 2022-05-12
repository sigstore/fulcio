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

package ca

import (
	"crypto/x509"
	"strings"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type CodeSigningCertificate struct {
	FinalCertificate *x509.Certificate
	FinalChain       []*x509.Certificate
	finalPEM         string
	finalChainPEM    []string
}

func CreateCSCFromPEM(cert string, chain []string) (*CodeSigningCertificate, error) {
	var c CodeSigningCertificate

	// convert to X509 and store both formats
	finalCert, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(cert))
	if err != nil {
		return nil, err
	}
	c.finalPEM = strings.TrimSpace(cert)
	c.FinalCertificate = finalCert[0]

	// convert to X509 and store both formats
	chainBytes := []byte(strings.Join(chain, ""))
	if len(chainBytes) != 0 {
		c.FinalChain, err = cryptoutils.UnmarshalCertificatesFromPEM(chainBytes)
		if err != nil {
			return nil, err
		}
		for _, cert := range chain {
			c.finalChainPEM = append(c.finalChainPEM, strings.TrimSpace(cert))
		}
	}
	return &c, nil
}

func CreateCSCFromDER(cert []byte, chain []*x509.Certificate) (*CodeSigningCertificate, error) {
	var (
		c   CodeSigningCertificate
		err error
	)

	// convert to X509 and store both formats
	c.finalPEM = strings.TrimSpace(string(cryptoutils.PEMEncode(cryptoutils.CertificatePEMType, cert)))
	c.FinalCertificate, err = x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	// convert to X509 and store both formats
	c.FinalChain = chain
	if err != nil {
		return nil, err
	}
	for _, chainCert := range c.FinalChain {
		c.finalChainPEM = append(c.finalChainPEM, strings.TrimSpace(string(cryptoutils.PEMEncode(cryptoutils.CertificatePEMType, chainCert.Raw))))
	}
	return &c, nil
}

func (c *CodeSigningCertificate) CertPEM() (string, error) {
	var err error
	if c.finalPEM == "" {
		finalPemBytes, err := cryptoutils.MarshalCertificateToPEM(c.FinalCertificate)
		if err == nil {
			c.finalPEM = strings.TrimSpace(string(finalPemBytes))
		}
	}
	return c.finalPEM, err
}

func (c *CodeSigningCertificate) ChainPEM() ([]string, error) {
	if c.finalChainPEM == nil && len(c.FinalChain) > 0 {
		for _, chainCert := range c.FinalChain {
			c.finalChainPEM = append(c.finalChainPEM, strings.TrimSpace(string(cryptoutils.PEMEncode(cryptoutils.CertificatePEMType, chainCert.Raw))))
		}
	}
	return c.finalChainPEM, nil
}
