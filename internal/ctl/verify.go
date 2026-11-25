// Copyright 2026 The Sigstore Authors.
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

package ctl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/md5" //nolint:gosec // RFC 5246 HashAlgorithm enum compatibility
	"crypto/rsa"
	_ "crypto/sha1" //nolint:gosec // RFC 5246 HashAlgorithm enum compatibility
	"crypto/sha256"
	_ "crypto/sha512" // Register SHA-384 and SHA-512
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignatureVerifier verifies RFC 6962 SCT signatures against a CT log public key.
type SignatureVerifier struct {
	pubKey crypto.PublicKey
}

// ParsePublicKeyPEM parses a single PEM-encoded PKIX public key.
func ParsePublicKeyPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(rest) > 0 {
		return nil, errors.New("extra data found after PEM key decoded")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// NewSignatureVerifier validates the CT log public key per RFC 6962 s2.1.4 and
// returns a SignatureVerifier.
func NewSignatureVerifier(pk crypto.PublicKey) (*SignatureVerifier, error) {
	switch k := pk.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("public key is RSA with < 2048 bits (size:%d)", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("public key is ECDSA, but not on the P256 curve")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pk)
	}
	return &SignatureVerifier{pubKey: pk}, nil
}

// VerifySCTSignature verifies that sct's signature is valid over the given
// entry type and DER certificate chain.
func (v *SignatureVerifier) VerifySCTSignature(sct SignedCertificateTimestamp, entryType LogEntryType, rawChain [][]byte) error {
	data, err := serializeSCTSignatureInput(sct, entryType, rawChain)
	if err != nil {
		return err
	}
	return verifyDigitallySigned(v.pubKey, data, sct.Signature)
}

func serializeSCTSignatureInput(sct SignedCertificateTimestamp, entryType LogEntryType, rawChain [][]byte) ([]byte, error) {
	if sct.SCTVersion != V1 {
		return nil, fmt.Errorf("unknown SCT version %d", sct.SCTVersion)
	}
	if len(rawChain) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	var b cryptobyte.Builder
	b.AddUint8(uint8(sct.SCTVersion))
	b.AddUint8(certificateTimestampSignatureType)
	b.AddUint64(sct.Timestamp)
	b.AddUint16(uint16(entryType))

	switch entryType {
	case X509LogEntryType:
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(rawChain[0])
		})
	case PrecertLogEntryType:
		if len(rawChain) < 2 {
			return nil, errors.New("no issuer cert available for precert leaf building")
		}
		leaf, err := x509.ParseCertificate(rawChain[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain[0] cert: %w", err)
		}
		issuer, err := x509.ParseCertificate(rawChain[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain[1] cert: %w", err)
		}

		var preIssuer *x509.Certificate
		if isPreIssuer(issuer) {
			if len(rawChain) < 3 {
				return nil, errors.New("no issuer cert available for pre-issuer")
			}
			preIssuer = issuer
			issuer, err = x509.ParseCertificate(rawChain[2])
			if err != nil {
				return nil, fmt.Errorf("failed to parse chain[2] cert: %w", err)
			}
		}

		defangedTBS, err := buildPrecertTBS(leaf.RawTBSCertificate, preIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to remove poison extension: %w", err)
		}

		issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		b.AddBytes(issuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(defangedTBS)
		})
	default:
		return nil, fmt.Errorf("unsupported entry type %d", entryType)
	}

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sct.Extensions)
	})
	return b.Bytes()
}

func isPreIssuer(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDExtKeyUsageCertificateTransparency) {
			return true
		}
	}
	return false
}

// buildPrecertTBS strips the CT poison extension (RFC 6962 s3.1) from a
// DER-encoded TBSCertificate while preserving all other fields verbatim.
// If preIssuer is non-nil, the issuer and AuthorityKeyId extension are also
// updated to match preIssuer as required by RFC 6962 s3.1.
func buildPrecertTBS(tbsData []byte, preIssuer *x509.Certificate) ([]byte, error) {
	input := cryptobyte.String(tbsData)
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("failed to parse TBSCertificate")
	}

	var out cryptobyte.Builder
	var buildErr error

	out.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// version [0] EXPLICIT Version DEFAULT v1 (optional)
		var rawField cryptobyte.String
		if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			if !tbs.ReadASN1Element(&rawField, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
				buildErr = errors.New("failed to parse TBSCertificate version")
				return
			}
			b.AddBytes(rawField)
		}

		// serialNumber CertificateSerialNumber
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate serialNumber")
			return
		}
		b.AddBytes(rawField)

		// signature AlgorithmIdentifier
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate signature")
			return
		}
		b.AddBytes(rawField)

		// issuer Name
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate issuer")
			return
		}
		if preIssuer != nil {
			b.AddBytes(preIssuer.RawIssuer)
		} else {
			b.AddBytes(rawField)
		}

		// validity Validity
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate validity")
			return
		}
		b.AddBytes(rawField)

		// subject Name
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate subject")
			return
		}
		b.AddBytes(rawField)

		// subjectPublicKeyInfo SubjectPublicKeyInfo
		if !tbs.ReadAnyASN1Element(&rawField, nil) {
			buildErr = errors.New("failed to parse TBSCertificate subjectPublicKeyInfo")
			return
		}
		b.AddBytes(rawField)

		// issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL
		if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
			if !tbs.ReadASN1Element(&rawField, cryptobyte_asn1.Tag(1).ContextSpecific()) {
				buildErr = errors.New("failed to parse TBSCertificate issuerUniqueID")
				return
			}
			b.AddBytes(rawField)
		}

		// subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
		if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
			if !tbs.ReadASN1Element(&rawField, cryptobyte_asn1.Tag(2).ContextSpecific()) {
				buildErr = errors.New("failed to parse TBSCertificate subjectUniqueID")
				return
			}
			b.AddBytes(rawField)
		}

		// extensions [3] EXPLICIT SEQUENCE OF Extension
		var extWrapper cryptobyte.String
		var present bool
		if !tbs.ReadOptionalASN1(&extWrapper, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) || !present {
			buildErr = errors.New("no extension of specified type present")
			return
		}
		if !tbs.Empty() {
			buildErr = errors.New("trailing data in TBSCertificate")
			return
		}

		var extSeq cryptobyte.String
		if !extWrapper.ReadASN1(&extSeq, cryptobyte_asn1.SEQUENCE) || !extWrapper.Empty() {
			buildErr = errors.New("failed to parse TBSCertificate extensions")
			return
		}

		var preIssuerAKI []byte
		if preIssuer != nil {
			for _, ext := range preIssuer.Extensions {
				if ext.Id.Equal(OIDExtensionAuthorityKeyID) {
					preIssuerAKI = ext.Value
					break
				}
			}
		}

		poisonCount := 0
		akiReplaced := false
		var keptExts [][]byte

		for !extSeq.Empty() {
			var extElem cryptobyte.String
			if !extSeq.ReadAnyASN1Element(&extElem, nil) {
				buildErr = errors.New("failed to parse extension element")
				return
			}
			extCopy := extElem
			var extBody cryptobyte.String
			var oid asn1.ObjectIdentifier
			if !extCopy.ReadASN1(&extBody, cryptobyte_asn1.SEQUENCE) || !extBody.ReadASN1ObjectIdentifier(&oid) {
				buildErr = errors.New("failed to parse extension OID")
				return
			}
			if oid.Equal(OIDExtensionCTPoison) {
				poisonCount++
				continue
			}
			if preIssuer != nil && oid.Equal(OIDExtensionAuthorityKeyID) {
				akiReplaced = true
				if preIssuerAKI == nil {
					continue
				}
				var akiBuilder cryptobyte.Builder
				akiBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(OIDExtensionAuthorityKeyID)
					b.AddASN1OctetString(preIssuerAKI)
				})
				akiBytes, err := akiBuilder.Bytes()
				if err != nil {
					buildErr = err
					return
				}
				keptExts = append(keptExts, akiBytes)
				continue
			}
			keptExts = append(keptExts, []byte(extElem))
		}

		if poisonCount == 0 {
			buildErr = errors.New("no extension of specified type present")
			return
		}
		if poisonCount > 1 {
			buildErr = errors.New("multiple extensions of specified type present")
			return
		}
		if preIssuer != nil && !akiReplaced && preIssuerAKI != nil {
			var akiBuilder cryptobyte.Builder
			akiBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDExtensionAuthorityKeyID)
				b.AddASN1OctetString(preIssuerAKI)
			})
			akiBytes, err := akiBuilder.Bytes()
			if err != nil {
				buildErr = err
				return
			}
			keptExts = append(keptExts, akiBytes)
		}

		if len(keptExts) > 0 {
			b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, ext := range keptExts {
						b.AddBytes(ext)
					}
				})
			})
		}
	})

	if buildErr != nil {
		return nil, buildErr
	}
	return out.Bytes()
}

func hashForAlgorithm(alg HashAlgorithm) (crypto.Hash, error) {
	switch alg {
	case MD5:
		return crypto.MD5, nil
	case SHA1:
		return crypto.SHA1, nil
	case SHA224:
		return crypto.SHA224, nil
	case SHA256:
		return crypto.SHA256, nil
	case SHA384:
		return crypto.SHA384, nil
	case SHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported Algorithm.Hash in signature: %d", alg)
	}
}

func verifyDigitallySigned(pubKey crypto.PublicKey, data []byte, sig DigitallySigned) error {
	hashType, err := hashForAlgorithm(sig.Algorithm.Hash)
	if err != nil {
		return err
	}
	h := hashType.New()
	_, _ = h.Write(data)
	digest := h.Sum(nil)

	switch sig.Algorithm.Signature {
	case RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("cannot verify RSA signature with %T key", pubKey)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, hashType, digest, sig.Signature); err != nil {
			return fmt.Errorf("failed to verify rsa signature: %w", err)
		}
	case ECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("cannot verify ECDSA signature with %T key", pubKey)
		}
		if !ecdsa.VerifyASN1(ecdsaKey, digest, sig.Signature) {
			return errors.New("failed to verify ECDSA signature")
		}
	default:
		return fmt.Errorf("unsupported Algorithm.Signature in signature: %d", sig.Algorithm.Signature)
	}
	return nil
}
