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
	"errors"
	"fmt"
	"math/big"

	signatureSubtle "github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle"

	"github.com/golang/protobuf/proto" //lint:ignore SA1019 needed for unmarshalling
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	ecdsaSignerKeyVersion   = 0
	ecdsaSignerTypeURL      = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
	ed25519SignerKeyVersion = 0
	ed25519SignerTypeURL    = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
)

// KeyHandleToSigner converts a key handle to the crypto.Signer interface.
// Heavily pulls from Tink's signature and subtle packages.
func KeyHandleToSigner(kh *keyset.Handle) (crypto.Signer, error) {
	// extract the key material from the key handle
	ks := insecurecleartextkeyset.KeysetMaterial(kh)

	k := getPrimaryKey(ks)
	if k == nil {
		return nil, errors.New("no enabled key found in keyset")
	}

	switch k.GetTypeUrl() {
	case ecdsaSignerTypeURL:
		// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/ecdsa_signer_key_manager.go#L48
		privKey := new(ecdsapb.EcdsaPrivateKey)
		if err := proto.Unmarshal(k.GetValue(), privKey); err != nil {
			return nil, fmt.Errorf("error unmarshalling ecdsa private key: %w", err)
		}
		if err := validateEcdsaPrivKey(privKey); err != nil {
			return nil, fmt.Errorf("error validating ecdsa private key: %w", err)
		}
		// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/subtle/ecdsa_signer.go#L39
		_, curve, _ := getECDSAParamNames(privKey.PublicKey.Params)
		p := new(ecdsa.PrivateKey)
		c := subtle.GetCurve(curve)
		p.PublicKey.Curve = c
		p.D = new(big.Int).SetBytes(privKey.GetKeyValue())
		p.PublicKey.X, p.PublicKey.Y = c.ScalarBaseMult(privKey.GetKeyValue())
		return p, nil
	case ed25519SignerTypeURL:
		// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/ed25519_signer_key_manager.go#L47
		privKey := new(ed25519pb.Ed25519PrivateKey)
		if err := proto.Unmarshal(k.GetValue(), privKey); err != nil {
			return nil, fmt.Errorf("error unmarshalling ed25519 private key: %w", err)
		}
		if err := validateEd25519PrivKey(privKey); err != nil {
			return nil, fmt.Errorf("error validating ed25519 private key: %w", err)
		}
		// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/subtle/ed25519_signer.go#L29
		p := ed25519.NewKeyFromSeed(privKey.GetKeyValue())
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.GetTypeUrl())
	}
}

// getPrimaryKey returns the first enabled key from a keyset.
func getPrimaryKey(ks *tinkpb.Keyset) *tinkpb.KeyData {
	for _, k := range ks.GetKey() {
		if k.GetKeyId() == ks.GetPrimaryKeyId() && k.GetStatus() == tinkpb.KeyStatusType_ENABLED {
			return k.GetKeyData()
		}
	}
	return nil
}

// validateEcdsaPrivKey validates the given ECDSAPrivateKey.
// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/ecdsa_signer_key_manager.go#L139
func validateEcdsaPrivKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, uint32(ecdsaSignerKeyVersion)); err != nil {
		return fmt.Errorf("ecdsa_signer_key_manager: invalid key: %w", err)
	}
	hash, curve, encoding := getECDSAParamNames(key.PublicKey.Params)
	return signatureSubtle.ValidateECDSAParams(hash, curve, encoding)
}

// getECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
// https://github.com/google/tink/blob/4cc630dfc711555f6bbbad64f8c573b39b7af500/go/signature/proto.go#L26
func getECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := commonpb.EllipticCurveType_name[int32(params.Curve)]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.Encoding)]
	return hashName, curveName, encodingName
}

// validateEd25519PrivKey validates the given ED25519PrivateKey.
// https://github.com/google/tink/blob/9753ffddd4d04aa56e0605ff4a0db46f2fb80529/go/signature/ed25519_signer_key_manager.go#L132
func validateEd25519PrivKey(key *ed25519pb.Ed25519PrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, uint32(ed25519SignerKeyVersion)); err != nil {
		return fmt.Errorf("ed25519_signer_key_manager: invalid key: %w", err)
	}
	if len(key.KeyValue) != ed25519.SeedSize {
		return fmt.Errorf("ed2219_signer_key_manager: invalid key length, got %d", len(key.KeyValue))
	}
	return nil
}
