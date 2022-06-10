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
	"fmt"
	"testing"
)

func TestValidLoadKeyPair(t *testing.T) {
	keypairs := []string{
		"ecdsa",
		"ed25519",
		"rsa4096",
		"openssl",
		"intermediate-2",
		"intermediate-3",
	}

	for _, keypair := range keypairs {
		keyPath := fmt.Sprintf("testdata/%s-key.pem", keypair)
		certPath := fmt.Sprintf("testdata/%s-cert.pem", keypair)

		_, err := loadKeyPair(certPath, keyPath, testKeyPass)
		if err != nil {
			t.Errorf("Failed to load key pair of type %s: %v", keypair, err)
		}
	}
}

func TestInvalidLoadKeyPair(t *testing.T) {
	keypairs := []string{
		"notca",
		"mismatch",
		"eku-chaining-violation",
	}

	for _, keypair := range keypairs {
		keyPath := fmt.Sprintf("testdata/%s-key.pem", keypair)
		certPath := fmt.Sprintf("testdata/%s-cert.pem", keypair)

		_, err := loadKeyPair(certPath, keyPath, testKeyPass)
		if err == nil {
			t.Errorf("Expected invalid key pair of type %s to fail to load", keypair)
		}
	}
}
