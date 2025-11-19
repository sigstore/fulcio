//go:build !cgo

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

package pkcs11ca

import (
	"errors"

	"github.com/sigstore/fulcio/pkg/ca/baseca"
)

type PKCS11CA struct {
	baseca.BaseCA
}

type Params struct {
	ConfigPath string
	RootID     string
	CAPath     *string
}

// NewPKCS11CA is a placeholder for erroring with a meaningful message if the
// binary has been built with CGO_ENABLED=0 tags.
func NewPKCS11CA(params Params) (*PKCS11CA, error) {
	return nil, errors.New("binary has been built with no cgo support, PKCS11 not supported")
}
