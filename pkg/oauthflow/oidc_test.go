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

package oauthflow

import (
	"errors"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/magiconair/properties/assert"
)

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func updateIDToken(idToken *oidc.IDToken, fieldName string, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(idToken))
	member := val.FieldByName(fieldName)
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

func TestTokenWithClaims(t *testing.T) {
	tests := []struct {
		name             string
		inputClaims      []byte
		expectedEmail    string
		expectedVerified bool
		expectedErr      error
	}{{
		name:             "token with nil claims",
		inputClaims:      nil,
		expectedEmail:    "",
		expectedVerified: false,
		expectedErr:      errors.New("oidc: claims not set"),
	}, {
		name:             "token with empty/no claims",
		inputClaims:      []byte(`{}`),
		expectedEmail:    "",
		expectedVerified: false,
		expectedErr:      nil,
	}, {
		name:             "token with non-verified claims set",
		inputClaims:      []byte(`{"email":"John.Doe@email.com"}`),
		expectedEmail:    "John.Doe@email.com",
		expectedVerified: false,
		expectedErr:      nil,
	}, {
		name:             "token with claims set",
		inputClaims:      []byte(`{"email":"John.Doe@email.com", "email_verified":true}`),
		expectedEmail:    "John.Doe@email.com",
		expectedVerified: true,
		expectedErr:      nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idToken := &oidc.IDToken{}
			updateIDToken(idToken, "claims", tt.inputClaims)
			actualEmail, actualVerified, actualErr := EmailFromIDToken(idToken)
			assert.Equal(t, actualEmail, tt.expectedEmail)
			assert.Equal(t, actualVerified, tt.expectedVerified)
			if actualErr != nil {
				assert.Equal(t, actualErr.Error(), tt.expectedErr.Error())
			} else {
				assert.Equal(t, actualErr, tt.expectedErr)
			}
		})
	}
}
