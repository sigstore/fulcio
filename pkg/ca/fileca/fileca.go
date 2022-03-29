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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ca/x509ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type fileCA struct {
	sync.RWMutex

	certs []*x509.Certificate
	key   crypto.Signer
}

// NewFileCA returns a file backed certificate authority. Expects paths to a
// certificate and key that are PEM encoded. The key must be encrypted
// according to RFC 1423
func NewFileCA(certPath, keyPath, keyPass string, watch bool) (ca.CertificateAuthority, error) {
	var fca fileCA

	var err error
	fca.certs, fca.key, err = loadKeyPair(certPath, keyPath, keyPass)
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

func (fca *fileCA) updateX509KeyPair(certs []*x509.Certificate, key crypto.Signer) {
	fca.Lock()
	defer fca.Unlock()

	// NB: We use the RWLock to unsure a reading thread can't get a mismatching
	// cert / key pair by reading the attributes halfway through the update
	// below.
	fca.certs = certs
	fca.key = key
}

func (fca *fileCA) getX509KeyPair() (*x509.Certificate, crypto.Signer) {
	fca.RLock()
	defer fca.RUnlock()
	return fca.certs[0], fca.key
}

// CreateCertificate issues code signing certificates
func (fca *fileCA) CreateCertificate(_ context.Context, subject *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	cert, err := x509ca.MakeX509(subject)
	if err != nil {
		return nil, err
	}

	rootCA, privateKey := fca.getX509KeyPair()

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, rootCA, subject.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	fca.RLock()
	defer fca.RUnlock()

	return ca.CreateCSCFromDER(subject, finalCertBytes, fca.certs)
}

func (fca *fileCA) Root(ctx context.Context) ([]byte, error) {
	fca.RLock()
	defer fca.RUnlock()

	return cryptoutils.MarshalCertificatesToPEM(fca.certs)
}
