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

package identity

import (
	"context"
	"crypto/x509"
)

type Principal interface {
	// Name is the email or subject of OIDC ID token. This value must match the
	// value signed in the proof of private key possession challenge.
	Name(ctx context.Context) string

	// Embed all SubjectAltName and custom x509 extension information into
	// certificate.
	Embed(ctx context.Context, cert *x509.Certificate) error
}
