//go:build purego
// +build purego

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

package x509ca

import (
	"errors"
)

// NewX509CA is a placeholder for erroring with a meaningful message if the
// binary has been built with purego tags.
func NewX509CA() (*X509CA, error) {
	return nil, errors.New("binary has been built with purego tags, PKCS11 not supported")
}
