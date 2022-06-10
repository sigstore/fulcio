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
//

package ca

import (
	"crypto"
	"crypto/x509"
	"sync"
)

// SignerWithChain provides a getter for a CA's certificate chain and signing key.
type SignerWithChain interface {
	GetSignerWithChain() ([]*x509.Certificate, crypto.Signer)
}

// SignerCerts holds a certificate chain and signer.
type SignerCerts struct {
	// Signer signs issued certificates
	Signer crypto.Signer
	// Certs contains the chain of certificates from intermediate to root
	Certs []*x509.Certificate
}

func (s *SignerCerts) GetSignerWithChain() ([]*x509.Certificate, crypto.Signer) {
	return s.Certs, s.Signer
}

// SignerCertsMutex holds a certificate chain and signer, and holds a reader lock
// when accessing the chain and signer. Use if a separate thread can concurrently
// update the chain and signer.
type SignerCertsMutex struct {
	sync.RWMutex

	// Certs contains the chain of certificates from intermediate to root
	Certs []*x509.Certificate
	// Signer signs issued certificates
	Signer crypto.Signer
}

func (s *SignerCertsMutex) GetSignerWithChain() ([]*x509.Certificate, crypto.Signer) {
	s.RLock()
	defer s.RUnlock()

	return s.Certs, s.Signer
}
