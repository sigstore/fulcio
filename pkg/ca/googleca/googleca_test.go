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

package googleca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/sigstore/fulcio/pkg/ca/cautils"
	"testing"
)

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckSignatureECDSA(t *testing.T) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	email := "test@gmail.com"
	if err := cautils.CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := cautils.CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := cautils.CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}

func TestCheckSignatureRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	failErr(t, err)

	email := "test@gmail.com"
	if err := cautils.CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := cautils.CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Try a bad email but "good" signature
	if err := cautils.CheckSignature(&priv.PublicKey, signature, "bad@email.com"); err == nil {
		t.Fatal("check should have failed")
	}
}
