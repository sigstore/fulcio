/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package oauthflow

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/oauth2"
)

type PKCEMethod string

const (
	PKCEPlain PKCEMethod = "plain"
	PKCES256  PKCEMethod = "S256"
)

type PKCE struct {
	Challenge string
	Method    PKCEMethod
	Value     string
}

func NewPKCE(method PKCEMethod) (*PKCE, error) {
	switch method {
	case PKCEPlain, PKCES256:
	default:
		return nil, errors.New("invalid PKCE method requested")
	}

	value, err := randStr()
	if err != nil {
		return nil, err
	}

	var challenge string
	if method == PKCES256 {
		h := sha256.New()
		_, _ = h.Write([]byte(value))
		challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	} else {
		challenge = value
	}

	return &PKCE{
		Challenge: challenge,
		Method:    method,
		Value:     value,
	}, nil
}

func (p *PKCE) AuthURLOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", string(p.Method)),
		oauth2.SetAuthURLParam("code_challenge", p.Challenge),
	}
}

func (p *PKCE) TokenURLOpts() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", p.Value),
	}
}
