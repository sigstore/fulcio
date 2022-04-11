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

	key := fca.Signer
	if _, ok = key.(ed25519.PrivateKey); !ok {
		t.Error(`first key should have been an ed25519 key`)
	}

	cert, key, err := loadKeyPair(newCert, newKey, testKeyPass)
	if err != nil {
		t.Fatal(`Failed to load new keypair`)
	}

	fca.updateX509KeyPair(cert, key)
	key = fca.Signer

	if _, ok = key.(*ecdsa.PrivateKey); !ok {
		t.Fatal(`file CA should have been updated with ecdsa key`)
	}
}
