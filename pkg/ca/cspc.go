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
	"crypto"
	"crypto/x509"
)

// CodeSigningPreCertificate holds a precertificate and chain.
type CodeSigningPreCertificate struct {
	// PreCert contains the precertificate. Not a valid certificate due to a critical poison extension.
	PreCert *x509.Certificate
	// CertChain contains the certificate chain to verify the precertificate.
	CertChain []*x509.Certificate
	// PrivateKey contains the signing key used to sign the precertificate. Will be used to sign the certificate.
	// Included in case the signing key is rotated in between precertificate generation and final issuance.
	PrivateKey crypto.Signer
}
