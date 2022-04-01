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

package x509ca

import (
	"math/big"
	"testing"
)

func TestGenerateSerialNumber(t *testing.T) {
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("unexpected error generating serial number: %v", err)
	}
	if serialNumber.Cmp(big.NewInt(0)) == -1 {
		t.Fatalf("serial number is negative: %v", serialNumber)
	}
	if serialNumber.Cmp(big.NewInt(0)) == 0 {
		t.Fatalf("serial number is 0: %v", serialNumber)
	}
	maxSerial := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil)
	// Serial number must be less than max serial number.
	if serialNumber.Cmp(maxSerial) >= 0 {
		t.Fatalf("serial number is too large: %v", serialNumber)
	}
}
