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

package ephemeralca

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestNewEphemeralCA(t *testing.T) {
	ca, err := NewEphemeralCA()
	if err != nil {
		t.Fatalf("unexpected error generating ephemeral CA: %v", err)
	}
	certs, signer := ca.GetSignerWithChain()
	if len(certs) != 1 {
		t.Fatalf("ca not set up")
	}
	rootCert := certs[0]
	if rootCert.NotAfter.Sub(rootCert.NotBefore) < time.Hour*24*365*10 {
		t.Fatalf("expected CA to have 10 year lifetime, got %v", rootCert.NotAfter.Sub(rootCert.NotBefore))
	}
	if !rootCert.IsCA {
		t.Fatalf("ca does not have IsCA bit set")
	}
	if rootCert.MaxPathLen != 1 {
		t.Fatalf("expected CA with path length of 1, got %d", rootCert.MaxPathLen)
	}
	if rootCert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("expected cert sign and crl sign key usage")
	}
	if err := cryptoutils.EqualKeys(signer.Public(), rootCert.PublicKey); err != nil {
		t.Fatalf("expected verification key and certificate key to match")
	}
}
