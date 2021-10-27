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

package challenges

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func Test_isSpiffeIDAllowed(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		spiffeID string
		want     bool
	}{{
		name:     "match",
		host:     "foobar.com",
		spiffeID: "spiffe://foobar.com/stuff",
		want:     true,
	}, {
		name:     "subdomain match",
		host:     "foobar.com",
		spiffeID: "spiffe://spife.foobar.com/stuff",
		want:     true,
	}, {
		name:     "subdomain mismatch",
		host:     "foo.foobar.com",
		spiffeID: "spiffe://spife.foobar.com/stuff",
		want:     false,
	}, {
		name:     "inverted mismatch",
		host:     "foo.foobar.com",
		spiffeID: "spiffe://foobar.com/stuff",
		want:     false,
	}, {
		name:     "no dot mismatch",
		host:     "foobar.com",
		spiffeID: "spiffe://foofoobar.com/stuff",
		want:     false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSpiffeIDAllowed(tt.host, tt.spiffeID); got != tt.want {
				t.Errorf("isSpiffeIDAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckSignatureECDSA(t *testing.T) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	email := "test@gmail.com"
	if err := CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}

func TestCheckSignatureRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	failErr(t, err)

	email := "test@gmail.com"
	if err := CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}
