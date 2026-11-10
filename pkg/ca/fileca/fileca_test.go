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

package fileca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"strings"
	"testing"
)

const testKeyPass = `password123`

func TestNewFileCA(t *testing.T) {
	_, err := NewFileCA(
		`testdata/ed25519-cert.pem`,
		`testdata/ed25519-key.pem`,
		testKeyPass,
		false,
	)
	if err != nil {
		t.Error(`Failed to load file CA from disk`)
	}
}

func TestCertUpdate(t *testing.T) {
	oldCert := `testdata/ed25519-cert.pem`
	oldKey := `testdata/ed25519-key.pem`
	newCert := `testdata/ecdsa-cert.pem`
	newKey := `testdata/ecdsa-key.pem`
	watch := false

	ca, err := NewFileCA(
		oldCert,
		oldKey,
		testKeyPass,
		watch,
	)
	if err != nil {
		t.Fatal(`Failed to load file CA from disk`)
	}

	fca, ok := ca.(*fileCA)
	if !ok {
		t.Fatal(`Bad CA type`)
	}

	_, key := fca.GetSignerWithChain()

	if _, ok = key.(ed25519.PrivateKey); !ok {
		t.Error(`first key should have been an ed25519 key`)
	}

	signerWithMutex, err := loadKeyPair(newCert, newKey, testKeyPass)
	if err != nil {
		t.Fatal(`Failed to load new keypair`)
	}

	if err := fca.updateX509KeyPair(signerWithMutex.Certs, signerWithMutex.Signer); err != nil {
		t.Fatalf("unexpected error updating key pair: %v", err)
	}
	_, key = fca.GetSignerWithChain()

	if _, ok = key.(*ecdsa.PrivateKey); !ok {
		t.Fatal(`file CA should have been updated with ecdsa key`)
	}
}

func TestCertUpdateRejectsMLDSASwitch(t *testing.T) {
	tests := []struct {
		name    string
		oldPair string
		newPair string
	}{
		{name: "classical to ML-DSA", oldPair: "ecdsa", newPair: "mldsa"},
		{name: "ML-DSA to classical", oldPair: "mldsa", newPair: "ecdsa"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := NewFileCA("testdata/"+tt.oldPair+"-cert.pem", "testdata/"+tt.oldPair+"-key.pem", testKeyPass, false)
			if err != nil {
				t.Fatalf("failed to load file CA from disk: %v", err)
			}
			fca := ca.(*fileCA)
			_, oldKey := fca.GetSignerWithChain()

			signerWithMutex, err := loadKeyPair("testdata/"+tt.newPair+"-cert.pem", "testdata/"+tt.newPair+"-key.pem", testKeyPass)
			if err != nil {
				t.Fatalf("failed to load new key pair: %v", err)
			}
			err = fca.updateX509KeyPair(signerWithMutex.Certs, signerWithMutex.Signer)
			if err == nil || !strings.Contains(err.Error(), "cannot switch between ML-DSA and non-ML-DSA") {
				t.Fatalf("expected error switching key type, got %v", err)
			}
			if _, key := fca.GetSignerWithChain(); key != oldKey {
				t.Fatal("file CA should have kept the original key")
			}
		})
	}
}

func TestCertUpdateMLDSA(t *testing.T) {
	ca, err := NewFileCA("testdata/mldsa-cert.pem", "testdata/mldsa-key.pem", testKeyPass, false)
	if err != nil {
		t.Fatalf("failed to load file CA from disk: %v", err)
	}
	fca := ca.(*fileCA)

	signerWithMutex, err := loadKeyPair("testdata/mldsa-cert.pem", "testdata/mldsa-key.pem", testKeyPass)
	if err != nil {
		t.Fatalf("failed to load new key pair: %v", err)
	}
	if err := fca.updateX509KeyPair(signerWithMutex.Certs, signerWithMutex.Signer); err != nil {
		t.Fatalf("unexpected error updating ML-DSA key pair: %v", err)
	}
	if _, key := fca.GetSignerWithChain(); key != signerWithMutex.Signer {
		t.Fatal("file CA should have been updated with the new ML-DSA key")
	}
}
