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
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
)

// Version represents the CT Version enum from RFC 6962 section 3.2:
//
//	enum { v1(0), (255) } Version;
type Version uint8

// V1 is the RFC 6962 v1 CT version.
const V1 Version = 0

// LogEntryType represents the LogEntryType enum from RFC 6962 section 3.1:
//
//	enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
type LogEntryType uint16

const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType LogEntryType = 1
)

// SignatureType constants from RFC 6962 section 3.2.
const (
	certificateTimestampSignatureType uint8 = 0
)

// URI paths for CT Log requests (RFC 6962 section 4).
const (
	AddChainPath    = "/ct/v1/add-chain"
	AddPreChainPath = "/ct/v1/add-pre-chain"
)

var (
	// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	// OIDExtensionCTSCT is defined in RFC 6962 s3.3.
	OIDExtensionCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	// OIDExtKeyUsageCertificateTransparency is the EKU OID for CT precertificate signing CAs (RFC 6962 s3.1).
	OIDExtKeyUsageCertificateTransparency = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	// OIDExtensionAuthorityKeyID is the X.509 Authority Key Identifier extension OID.
	OIDExtensionAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// HashAlgorithm enum from RFC 5246 s7.4.1.4.1.
type HashAlgorithm uint8

const (
	HashNone HashAlgorithm = 0
	MD5      HashAlgorithm = 1
	SHA1     HashAlgorithm = 2
	SHA224   HashAlgorithm = 3
	SHA256   HashAlgorithm = 4
	SHA384   HashAlgorithm = 5
	SHA512   HashAlgorithm = 6
)

// SignatureAlgorithm enum from RFC 5246 s7.4.1.4.1.
type SignatureAlgorithm uint8

const (
	Anonymous SignatureAlgorithm = 0
	RSA       SignatureAlgorithm = 1
	DSA       SignatureAlgorithm = 2
	ECDSA     SignatureAlgorithm = 3
)

// SignatureAndHashAlgorithm identifies the hash and signature algorithms
// used in a DigitallySigned structure (RFC 5246 s7.4.1.4.1).
type SignatureAndHashAlgorithm struct {
	Hash      HashAlgorithm
	Signature SignatureAlgorithm
}

// DigitallySigned represents a TLS digitally-signed struct (RFC 5246 s4.7).
type DigitallySigned struct {
	Algorithm SignatureAndHashAlgorithm
	Signature []byte
}

// MarshalTLS encodes DigitallySigned in TLS wire format.
func (d DigitallySigned) MarshalTLS() ([]byte, error) {
	if len(d.Signature) > math.MaxUint16 {
		return nil, fmt.Errorf("signature length %d exceeds maximum %d", len(d.Signature), math.MaxUint16)
	}
	var b cryptobyte.Builder
	b.AddUint8(uint8(d.Algorithm.Hash))
	b.AddUint8(uint8(d.Algorithm.Signature))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(d.Signature)
	})
	return b.Bytes()
}

// UnmarshalDigitallySigned decodes a TLS-encoded DigitallySigned struct.
func UnmarshalDigitallySigned(data []byte) (DigitallySigned, error) {
	s := cryptobyte.String(data)
	var hashAlg, sigAlg uint8
	var sig cryptobyte.String
	if !s.ReadUint8(&hashAlg) || !s.ReadUint8(&sigAlg) || !s.ReadUint16LengthPrefixed(&sig) {
		return DigitallySigned{}, errors.New("failed to unmarshal DigitallySigned")
	}
	if !s.Empty() {
		return DigitallySigned{}, fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(s))
	}
	sigCopy := make([]byte, len(sig))
	copy(sigCopy, sig)
	return DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{
			Hash:      HashAlgorithm(hashAlg),
			Signature: SignatureAlgorithm(sigAlg),
		},
		Signature: sigCopy,
	}, nil
}

// SignedCertificateTimestamp represents an RFC 6962 section 3.2 SCT.
type SignedCertificateTimestamp struct {
	SCTVersion Version
	LogID      [sha256.Size]byte
	Timestamp  uint64
	Extensions []byte
	Signature  DigitallySigned
}

// MarshalTLS encodes a SignedCertificateTimestamp in TLS wire format (RFC 6962 s3.2).
func (sct SignedCertificateTimestamp) MarshalTLS() ([]byte, error) {
	if len(sct.Extensions) > math.MaxUint16 {
		return nil, fmt.Errorf("SCT extensions length %d exceeds maximum %d", len(sct.Extensions), math.MaxUint16)
	}
	sigBytes, err := sct.Signature.MarshalTLS()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(uint8(sct.SCTVersion))
	b.AddBytes(sct.LogID[:])
	b.AddUint64(sct.Timestamp)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sct.Extensions)
	})
	b.AddBytes(sigBytes)
	return b.Bytes()
}

// MarshalSCTList encodes one or more SCTs into a TLS-encoded
// SignedCertificateTimestampList (RFC 6962 s3.3).
func MarshalSCTList(scts []SignedCertificateTimestamp) ([]byte, error) {
	if len(scts) == 0 {
		return nil, errors.New("SCT list must not be empty")
	}
	var b cryptobyte.Builder
	var marshalErr error
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, sct := range scts {
			sctBytes, err := sct.MarshalTLS()
			if err != nil {
				marshalErr = err
				return
			}
			if len(sctBytes) == 0 || len(sctBytes) > math.MaxUint16 {
				marshalErr = fmt.Errorf("serialized SCT length %d out of bounds", len(sctBytes))
				return
			}
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(sctBytes)
			})
		}
	})
	if marshalErr != nil {
		return nil, marshalErr
	}
	return b.Bytes()
}

// AddChainRequest is the JSON request body for add-chain and add-pre-chain (RFC 6962 s4.1-4.2).
type AddChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// AddChainResponse is the JSON response from add-chain and add-pre-chain (RFC 6962 s4.1-4.2).
type AddChainResponse struct {
	SCTVersion Version `json:"sct_version"`
	ID         []byte  `json:"id"`
	Timestamp  uint64  `json:"timestamp"`
	Extensions string  `json:"extensions"`
	Signature  []byte  `json:"signature"`
}

// BuildCTChain constructs a DER-encoded certificate chain for submitting to the CT log.
func BuildCTChain(cert *x509.Certificate, chain []*x509.Certificate) [][]byte {
	ctChain := make([][]byte, 0, 1+len(chain))
	ctChain = append(ctChain, cert.Raw)
	for _, c := range chain {
		ctChain = append(ctChain, c.Raw)
	}
	return ctChain
}

// ToAddChainResponse converts a SignedCertificateTimestamp to an AddChainResponse.
func ToAddChainResponse(sct *SignedCertificateTimestamp) (*AddChainResponse, error) {
	sig, err := sct.Signature.MarshalTLS()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}
	id := make([]byte, sha256.Size)
	copy(id, sct.LogID[:])
	return &AddChainResponse{
		SCTVersion: sct.SCTVersion,
		Timestamp:  sct.Timestamp,
		Extensions: base64.StdEncoding.EncodeToString(sct.Extensions),
		ID:         id,
		Signature:  sig,
	}, nil
}
