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

package tinkca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
)

type TestStruct struct {
	keyTemplate *tink_go_proto.KeyTemplate
	h           hash.Hash
}

func TestKeyHandleToSignerECDSA(t *testing.T) {
	supportedKeyTypes := []TestStruct{
		{
			keyTemplate: signature.ECDSAP256KeyWithoutPrefixTemplate(),
			h:           sha256.New(),
		},
		{
			keyTemplate: signature.ECDSAP384KeyWithoutPrefixTemplate(),
			h:           sha512.New(),
		},
		{
			keyTemplate: signature.ECDSAP521KeyWithoutPrefixTemplate(),
			h:           sha512.New(),
		},
	}
	for _, kt := range supportedKeyTypes {
		kh, err := keyset.NewHandle(kt.keyTemplate)
		if err != nil {
			t.Fatalf("error creating ECDSA key handle: %v", err)
		}
		// convert to crypto.Signer interface
		signer, err := KeyHandleToSigner(kh)
		if err != nil {
			t.Fatalf("error converting ECDSA key handle to signer: %v", err)
		}
		msg := []byte("hello there")

		// sign with key handle, verify with signer public key
		tinkSigner, err := signature.NewSigner(kh)
		if err != nil {
			t.Fatalf("error creating tink signer: %v", err)
		}
		sig, err := tinkSigner.Sign(msg)
		if err != nil {
			t.Fatalf("error signing with tink signer: %v", err)
		}
		kt.h.Write(msg)
		digest := kt.h.Sum(nil)
		if !ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest, sig) {
			t.Fatalf("signature from tink signer did not match")
		}

		// sign with signer, verify with key handle
		sig, err = ecdsa.SignASN1(rand.Reader, signer.(*ecdsa.PrivateKey), digest)
		if err != nil {
			t.Fatalf("error signing with crypto signer: %v", err)
		}
		pubkh, err := kh.Public()
		if err != nil {
			t.Fatalf("error fetching public key handle: %v", err)
		}
		v, err := signature.NewVerifier(pubkh)
		if err != nil {
			t.Fatalf("error creating tink verifier: %v", err)
		}
		if err := v.Verify(sig, msg); err != nil {
			t.Fatalf("error verifying with tink verifier: %v", err)
		}
	}
}

func TestKeyHandleToSignerED25519(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ED25519KeyWithoutPrefixTemplate())
	if err != nil {
		t.Fatalf("error creating ED25519 key handle: %v", err)
	}
	// convert to crypto.Signer interface
	signer, err := KeyHandleToSigner(kh)
	if err != nil {
		t.Fatalf("error converting ED25519 key handle to signer: %v", err)
	}
	msg := []byte("hello there")

	// sign with key handle, verify with signer public key
	tinkSigner, err := signature.NewSigner(kh)
	if err != nil {
		t.Fatalf("error creating tink signer: %v", err)
	}
	sig, err := tinkSigner.Sign(msg)
	if err != nil {
		t.Fatalf("error signing with tink signer: %v", err)
	}
	if !ed25519.Verify(signer.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatalf("signature from tink signer did not match")
	}

	// sign with signer, verify with key handle
	sig = ed25519.Sign(signer.(ed25519.PrivateKey), msg)
	if err != nil {
		t.Fatalf("error signing with crypto signer: %v", err)
	}
	pubkh, err := kh.Public()
	if err != nil {
		t.Fatalf("error fetching public key handle: %v", err)
	}
	v, err := signature.NewVerifier(pubkh)
	if err != nil {
		t.Fatalf("error creating tink verifier: %v", err)
	}
	if err := v.Verify(sig, msg); err != nil {
		t.Fatalf("error verifying with tink verifier: %v", err)
	}
}
