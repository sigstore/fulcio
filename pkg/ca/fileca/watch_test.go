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
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func cp(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func TestIOWatch(t *testing.T) {
	dir, err := os.MkdirTemp("", "fileca")
	if err != nil {
		t.Fatal(`Failed to create temp dir`)
	}
	// defer os.RemoveAll(dir)

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	// Copy initial certs into place
	err = cp("testdata/ed25519-key.pem", keyPath)
	if err != nil {
		t.Fatal(`Couldn't copy test data to temp file`)
	}
	err = cp("testdata/ed25519-cert.pem", certPath)
	if err != nil {
		t.Fatal(`Couldn't copy test data to temp file`)
	}

	// Set up callback trap
	var received []struct {
		certs []*x509.Certificate
		key   crypto.Signer
	}
	callback := func(certs []*x509.Certificate, key crypto.Signer) {
		received = append(received, struct {
			certs []*x509.Certificate
			key   crypto.Signer
		}{certs, key})
	}

	// Set up watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}

	err = watcher.Add(certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = watcher.Add(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	go ioWatch(certPath, keyPath, testKeyPass, watcher, callback)

	// Change the certs in place
	err = cp("testdata/ecdsa-key.pem", keyPath)
	if err != nil {
		t.Fatal(`Couldn't copy test data to temp file`)
	}
	err = cp("testdata/ecdsa-cert.pem", certPath)
	if err != nil {
		t.Fatal(`Couldn't copy test data to temp file`)
	}

	// Sleep for a bit to make sure that iowatch thread
	// does its thing.
	// TODO: This is hacky. Find a better way
	time.Sleep(1 * time.Second)

	// Test that we noticed the update and loaded the new
	// certificate
	if len(received) == 0 {
		t.Error("iowatcher should have seen at least 1 update")
	}

	if _, ok := received[0].key.(*ecdsa.PrivateKey); !ok {
		t.Error("Should have loaded an ecdsa private key on update")
	}
}
