/*
Copyright © 2021 Dan Lorenc <lorenc.d@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	failErr(t, err)

	email := "test@gmail.com"
	if Check(pub, "foo", email) {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	sig := base64.StdEncoding.EncodeToString(signature)
	if !Check(pub, sig, email) {
		t.Fatal("check should have passed")
	}

	// Try a bad email but "good" signature
	if Check(pub, sig, "bad@email.com") {
		t.Fatal("check should have failed")
	}
}
