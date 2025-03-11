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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckSignature(t *testing.T) {
	tts := []struct {
		name         string
		keys         func() (crypto.PublicKey, crypto.PrivateKey)
		hashFunc     crypto.Hash
		signHashFunc crypto.Hash
	}{
		{
			name: "ecdsa-p256",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA256,
			signHashFunc: crypto.SHA256,
		},
		{
			name: "ecdsa-p384",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA384,
			signHashFunc: crypto.SHA384,
		},
		{
			name: "ecdsa-p521",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA512,
			signHashFunc: crypto.SHA512,
		},
		{
			name: "rsa-2048",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA256,
			signHashFunc: crypto.SHA256,
		},
		{
			name: "rsa-3072",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := rsa.GenerateKey(rand.Reader, 3072)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA256,
			signHashFunc: crypto.SHA256,
		},
		{
			name: "rsa-4096",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				priv, _ := rsa.GenerateKey(rand.Reader, 4096)
				return priv.Public(), priv
			},
			hashFunc:     crypto.SHA256,
			signHashFunc: crypto.SHA256,
		},
		{
			name: "ed25519",
			keys: func() (crypto.PublicKey, crypto.PrivateKey) {
				pub, priv, _ := ed25519.GenerateKey(rand.Reader)
				return pub, priv
			},
			hashFunc:     crypto.SHA512,
			signHashFunc: crypto.Hash(0),
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := tt.keys()

			email := "test@gmail.com"
			if err := CheckSignature(pub, []byte("foo"), email); err == nil {
				t.Fatal("check should have failed")
			}

			signerVerifier, err := signature.LoadSignerVerifier(priv, tt.signHashFunc)
			failErr(t, err)

			signature, err := signerVerifier.SignMessage(strings.NewReader(email))
			failErr(t, err)

			if err := CheckSignatureWithVerifier(signerVerifier, signature, email); err != nil {
				t.Fatal(err)
			}
			if err := CheckSignature(pub, signature, email); err != nil {
				t.Fatal(err)
			}

			// Nil key should fail
			if err := CheckSignature(nil, signature, email); err == nil {
				t.Error("nil public key should raise error")
			}

			// Try a bad email but "good" signature
			if err := CheckSignature(pub, signature, "bad@email.com"); err == nil {
				t.Fatal("check should have failed")
			}
		})
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
