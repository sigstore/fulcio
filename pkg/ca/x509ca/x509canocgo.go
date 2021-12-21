//go:build !cgo
// +build !cgo

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

type Params struct {
	ConfigPath string
	RootID     string
	CAPath     *string
}

// NewX509CA is a placeholder for erroring with a meaningful message if the
// binary has been built with CGO_ENABLED=0 tags.
func NewX509CA(params Params) (*X509CA, error) {
	return nil, errors.New("binary has been built with no cgo support, PKCS11 not supported")
}
