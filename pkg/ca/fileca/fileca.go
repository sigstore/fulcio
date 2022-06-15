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
	"crypto/x509"

	"github.com/fsnotify/fsnotify"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/intermediateca"
)

type fileCA struct {
	intermediateca.IntermediateCA
}

// NewFileCA returns a file backed certificate authority. Expects paths to a
// certificate and key that are PEM encoded. The key must be encrypted
// according to RFC 1423
func NewFileCA(certPath, keyPath, keyPass string, watch bool) (ca.CertificateAuthority, error) {
	var fca fileCA

	var err error
	fca.SignerWithChain, err = loadKeyPair(certPath, keyPath, keyPass)
	if err != nil {
		return nil, err
	}

	if watch {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}
		err = watcher.Add(certPath)
		if err != nil {
			return nil, err
		}
		err = watcher.Add(keyPath)
		if err != nil {
			return nil, err
		}

		go ioWatch(certPath, keyPath, keyPass, watcher, fca.updateX509KeyPair)
	}

	return &fca, err
}

func (fca *fileCA) updateX509KeyPair(certs []*x509.Certificate, signer crypto.Signer) {
	scm := fca.SignerWithChain.(*ca.SignerCertsMutex)
	scm.Lock()
	defer scm.Unlock()

	// NB: We use a lock to ensure a reading thread can't get a mismatching
	// cert / key pair by reading the attributes halfway through the update
	// below.
	scm.Certs = certs
	scm.Signer = signer
}
