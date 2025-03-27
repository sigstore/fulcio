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

package tinkca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"
)

func curveFromTinkECDSACurveType(curveType tinkecdsa.CurveType) (elliptic.Curve, error) {
	switch curveType {
	case tinkecdsa.NistP256:
		return elliptic.P256(), nil
	case tinkecdsa.NistP384:
		return elliptic.P384(), nil
	case tinkecdsa.NistP521:
		return elliptic.P521(), nil
	default:
		// Should never happen.
		return nil, fmt.Errorf("unsupported curve: %v", curveType)
	}
}

// KeyHandleToSigner constructs a [crypto.Signer] from a Tink [keyset.Handle]'s
// primary key.
//
// NOTE: Tink validates keys on [keyset.Handle] creation.
func KeyHandleToSigner(kh *keyset.Handle) (crypto.Signer, error) {
	primary, err := kh.Primary()
	if err != nil {
		return nil, err
	}

	switch privateKey := primary.Key().(type) {
	case *tinkecdsa.PrivateKey:
		publicKey, err := privateKey.PublicKey()
		if err != nil {
			return nil, err
		}
		ecdsaPublicKey := publicKey.(*tinkecdsa.PublicKey)

		curve, err := curveFromTinkECDSACurveType(ecdsaPublicKey.Parameters().(*tinkecdsa.Parameters).CurveType())
		if err != nil {
			return nil, err
		}

		// Encoded as: 0x04 || X || Y.
		// See https://github.com/tink-crypto/tink-go/blob/v2.3.0/signature/ecdsa/key.go#L335
		publicPoint := ecdsaPublicKey.PublicPoint()
		xy := publicPoint[1:]
		pk := new(ecdsa.PrivateKey)
		pk.Curve = curve
		pk.X = new(big.Int).SetBytes(xy[:len(xy)/2])
		pk.Y = new(big.Int).SetBytes(xy[len(xy)/2:])
		pk.D = new(big.Int).SetBytes(privateKey.PrivateKeyValue().Data(insecuresecretdataaccess.Token{}))
		return pk, err
	case *tinked25519.PrivateKey:
		return ed25519.NewKeyFromSeed(privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})), err
	default:
		return nil, fmt.Errorf("unsupported key type: %T", primary.Key())
	}
}
