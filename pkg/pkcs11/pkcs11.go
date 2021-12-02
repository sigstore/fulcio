//go:build !purego
// +build !purego

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

package pkcs11

import (
	"github.com/ThalesIgnite/crypto11"
)

func InitHSMCtx(configPath string) (*crypto11.Context, error) {
	p11Ctx, err := crypto11.ConfigureFromFile(configPath)
	if err != nil {
		return nil, err
	}
	return p11Ctx, nil
}
