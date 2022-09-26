// Copyright 2022 The Sigstore Authors.
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

package username

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/sigstore/fulcio/pkg/certificate"
)

// OtherName describes a name related to a certificate which is not in one
// of the standard name formats. RFC 5280, 4.2.1.6:
//
//	OtherName ::= SEQUENCE {
//	     type-id    OBJECT IDENTIFIER,
//	     value      [0] EXPLICIT ANY DEFINED BY type-id }
//
// OtherName for Fulcio-issued certificates only supports UTF-8 strings as values.
type OtherName struct {
	ID    asn1.ObjectIdentifier
	Value string `asn1:"utf8,explicit,tag:0"`
}

// MarshalSANS creates a Subject Alternative Name extension
// with an OtherName sequence. RFC 5280, 4.2.1.6:
//
// SubjectAltName ::= GeneralNames
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
// GeneralName ::= CHOICE {
//
//	otherName                       [0]     OtherName,
//	... }
func MarshalSANS(name string, critical bool) (*pkix.Extension, error) {
	var rawValues []asn1.RawValue
	o := OtherName{
		ID:    certificate.OIDOtherName,
		Value: name,
	}
	bytes, err := asn1.MarshalWithParams(o, "tag:0")
	if err != nil {
		return nil, err
	}
	rawValues = append(rawValues, asn1.RawValue{FullBytes: bytes})

	sans, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, err
	}
	return &pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		Critical: critical,
		Value:    sans,
	}, nil
}

func UnmarshalSANS(exts []pkix.Extension) (string, error) {
	var otherNames []string

	for _, e := range exts {
		if !e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}

		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(e.Value, &seq)
		if err != nil {
			return "", err
		} else if len(rest) != 0 {
			return "", fmt.Errorf("trailing data after X.509 extension")
		}
		if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
			return "", asn1.StructuralError{Msg: "bad SAN sequence"}
		}

		rest = seq.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				return "", err
			}

			// skip all GeneralName fields except OtherName
			if v.Tag != 0 {
				continue
			}

			var other OtherName
			_, err := asn1.UnmarshalWithParams(v.FullBytes, &other, "tag:0")
			if err != nil {
				return "", fmt.Errorf("could not parse requested OtherName SAN: %v", err)
			}
			if !other.ID.Equal(certificate.OIDOtherName) {
				return "", fmt.Errorf("unexpected OID for OtherName, expected %v, got %v", certificate.OIDOtherName, other.ID)
			}
			otherNames = append(otherNames, other.Value)
		}
	}

	if len(otherNames) == 0 {
		return "", errors.New("no OtherName found")
	}
	if len(otherNames) != 1 {
		return "", errors.New("expected only one OtherName")
	}

	return otherNames[0], nil
}
