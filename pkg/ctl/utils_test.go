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

package ctl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"reflect"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

func TestBuildCTChain(t *testing.T) {
	certs := []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "leaf"}},
		{Subject: pkix.Name{CommonName: "sub"}},
		{Subject: pkix.Name{CommonName: "root"}},
	}
	ctChain := BuildCTChain(certs[0], certs[1:3])

	if len(ctChain) != len(certs) {
		t.Fatalf("CT chain length does not equal certificate chain length, got %v, expected %v", len(ctChain), len(certs))
	}

	for i := 0; i < len(certs); i++ {
		if !reflect.DeepEqual(ctChain[i].Data, certs[i].Raw) {
			t.Fatal("CT certificate and certificate do not match")
		}
	}
}

func TestToAddChainResponse(t *testing.T) {
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: [32]byte{1, 2, 3, 4}},
		Timestamp:  12345,
		Extensions: ct.CTExtensions{1, 2, 3},
		Signature:  ct.DigitallySigned{Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA1, Signature: tls.ECDSA}},
	}

	resp, err := ToAddChainResponse(sct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.SCTVersion != sct.SCTVersion {
		t.Fatal("SCT version does not match")
	}
	if !reflect.DeepEqual(resp.ID, sct.LogID.KeyID[:]) {
		t.Fatal("ID does not match")
	}
	if resp.Timestamp != sct.Timestamp {
		t.Fatal("timestamp does not match")
	}
	if resp.Extensions != base64.StdEncoding.EncodeToString(sct.Extensions) {
		t.Fatal("timestamp does not match")
	}
	sig, err := tls.Marshal(sct.Signature)
	if err != nil {
		t.Fatal("error marshalling signature")
	}
	if !reflect.DeepEqual(resp.Signature, sig) {
		t.Fatal("signature does not match")
	}
}
