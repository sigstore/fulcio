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
	"strings"
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

func TestEmailFromIDToken(t *testing.T) {
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
		expectedErr:      errors.New("token missing email claim"),
	}, {
		name:             "token with non-verified claims set",
		inputClaims:      []byte(`{"email":"John.Doe@email.com"}`),
		expectedEmail:    "John.Doe@email.com",
		expectedVerified: false,
		expectedErr:      nil,
	}, {
		name:        "token missing email claim",
		inputClaims: []byte(`{"email_verified": true}`),
		expectedErr: errors.New("token missing email claim"),
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

func TestIssuerFromIDToken(t *testing.T) {
	expectedIss := "issuer"
	idToken := &oidc.IDToken{Issuer: expectedIss}

	// Test with no claims path
	iss, err := IssuerFromIDToken(idToken, "")
	if err != nil {
		t.Fatalf("unexpected error generating issuer: %v", err)
	}
	if iss != expectedIss {
		t.Fatalf("unexpected issuer, expected %s, got %s", expectedIss, iss)
	}

	// append additional claims
	otherExpectedIss := "otherIssuer"
	updateIDToken(idToken, "claims", []byte(`{"other_issuer":"otherIssuer"}`))
	iss, err = IssuerFromIDToken(idToken, "$.other_issuer")
	if err != nil {
		t.Fatalf("unexpected error generating issuer: %v", err)
	}
	if iss != otherExpectedIss {
		t.Fatalf("unexpected issuer, expected %s, got %s", otherExpectedIss, iss)
	}

	// failure with invalid claim path
	_, err = IssuerFromIDToken(idToken, "$.invalid")
	if err == nil || !strings.Contains(err.Error(), "unknown key invalid") {
		t.Fatalf("expected error fetching invalid key, got %v", err)
	}

	// failure with invalid claims
	updateIDToken(idToken, "claims", []byte(`{`))
	_, err = IssuerFromIDToken(idToken, "$.other_issuer")
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("expected error with malformed ID token, got %v", err)
	}
}
