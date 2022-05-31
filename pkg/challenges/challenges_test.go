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

	"github.com/sigstore/sigstore/pkg/cryptoutils"
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
	if err := CheckSignature(&priv.PublicKey, []byte("foo"), email); err == nil {
		t.Fatal("check should have failed")
	}

	h := sha256.Sum256([]byte(email))
	signature, err := priv.Sign(rand.Reader, h[:], crypto.SHA256)
	failErr(t, err)

	if err := CheckSignature(&priv.PublicKey, signature, email); err != nil {
		t.Fatal(err)
	}

	// Nil key should fail
	if err := CheckSignature(nil, signature, email); err == nil {
		t.Error("nil public key should raise error")
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

func TestParsePublicKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	failErr(t, err)

	// succeeds with PEM-encoded key
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	failErr(t, err)
	pubKey, err := ParsePublicKey(string(pemKey))
	failErr(t, err)
	if err := cryptoutils.EqualKeys(pubKey, priv.Public()); err != nil {
		t.Fatalf("expected equal public keys")
	}

	// succeeds with DER-encoded key
	derKey, err := cryptoutils.MarshalPublicKeyToDER(priv.Public())
	failErr(t, err)
	pubKey, err = ParsePublicKey(string(derKey))
	failErr(t, err)
	if err := cryptoutils.EqualKeys(pubKey, priv.Public()); err != nil {
		t.Fatalf("expected equal public keys")
	}

	// fails with no public key
	_, err = ParsePublicKey("")
	if err == nil || err.Error() != "public key not provided" {
		t.Fatalf("expected error parsing no public key, got %v", err)
	}

	// fails with invalid public key (private key)
	pemPrivKey, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	failErr(t, err)
	_, err = ParsePublicKey(string(pemPrivKey))
	if err == nil || err.Error() != "error parsing PEM or DER encoded public key" {
		t.Fatalf("expected error parsing invalid public key, got %v", err)
	}
}
