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
)

func ioWatch(certPath, keyPath, keyPass string, watcher *fsnotify.Watcher, callback func([]*x509.Certificate, crypto.Signer)) {
	for event := range watcher.Events {
		if event.Op&fsnotify.Write == fsnotify.Write {
			certs, key, err := loadKeyPair(certPath, keyPath, keyPass)
			if err != nil {
				// Don't sweat it if this errors out. One file might
				// have updated and the other isn't causing a key-pair
				// mismatch
				continue
			}

			callback(certs, key)
		}
	}
}
