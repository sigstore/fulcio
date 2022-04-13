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
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type CodeSigningCertificate struct {
	Subject          *challenges.ChallengeResult
	FinalCertificate *x509.Certificate
	FinalChain       []*x509.Certificate
	finalPEM         string
	finalChainPEM    []string
}

// CodeSigningPreCertificate holds a precertificate and chain.
type CodeSigningPreCertificate struct {
	// Subject contains information about the OIDC identity of the caller.
	Subject *challenges.ChallengeResult
	// PreCert contains the precertificate. Not a valid certificate due to a critical poison extension.
	PreCert *x509.Certificate
	// CertChain contains the certificate chain to verify the precertificate.
	CertChain []*x509.Certificate
	// PrivateKey contains the signing key used to sign the precertificate. Will be used to sign the certificate.
	// Included in case the signing key is rotated in between precertificate generation and final issuance.
	PrivateKey crypto.Signer
}

func CreateCSCFromPEM(subject *challenges.ChallengeResult, cert string, chain []string) (*CodeSigningCertificate, error) {
	c := &CodeSigningCertificate{
		Subject: subject,
	}

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
	return c, nil
}

func CreateCSCFromDER(subject *challenges.ChallengeResult, cert []byte, chain []*x509.Certificate) (c *CodeSigningCertificate, err error) {
	c = &CodeSigningCertificate{
		Subject: subject,
	}

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
	return c, nil
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

// CertificateAuthority implements certificate creation with a detached SCT and fetching the CA trust bundle.
type CertificateAuthority interface {
	CreateCertificate(ctx context.Context, challenge *challenges.ChallengeResult) (*CodeSigningCertificate, error)
	Root(ctx context.Context) ([]byte, error)
}

// EmbeddedSCTCA implements precertificate and certificate issuance. Certificates will contain an embedded SCT.
type EmbeddedSCTCA interface {
	CreatePrecertificate(ctx context.Context, challenge *challenges.ChallengeResult) (*CodeSigningPreCertificate, error)
	IssueFinalCertificate(ctx context.Context, precert *CodeSigningPreCertificate, sct *ct.SignedCertificateTimestamp) (*CodeSigningCertificate, error)
}

// ValidationError indicates that there is an issue with the content in the HTTP Request that
// should result in an HTTP 400 Bad Request error being returned to the client
type ValidationError error
