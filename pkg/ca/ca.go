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

	"github.com/sigstore/fulcio/pkg/identity"
)

// CertificateAuthority implements certificate creation with a detached SCT and
// fetching the CA trust bundle.
type CertificateAuthority interface {
	CreateCertificate(context.Context, identity.Principal, crypto.PublicKey) (*CodeSigningCertificate, error)
	TrustBundle(ctx context.Context) ([][]*x509.Certificate, error)
	Close() error
}
