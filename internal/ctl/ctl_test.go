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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}

func TestBuildCTChain(t *testing.T) {
	certs := []*x509.Certificate{
		{Raw: []byte("leaf"), Subject: pkix.Name{CommonName: "leaf"}},
		{Raw: []byte("sub"), Subject: pkix.Name{CommonName: "sub"}},
		{Raw: []byte("root"), Subject: pkix.Name{CommonName: "root"}},
	}
	ctChain := BuildCTChain(certs[0], certs[1:3])

	if len(ctChain) != len(certs) {
		t.Fatalf("CT chain length = %d, want %d", len(ctChain), len(certs))
	}
	for i := range certs {
		if !bytes.Equal(ctChain[i], certs[i].Raw) {
			t.Fatalf("chain[%d] = %q, want %q", i, ctChain[i], certs[i].Raw)
		}
	}
}

func TestToAddChainResponse(t *testing.T) {
	sct := &SignedCertificateTimestamp{
		SCTVersion: V1,
		LogID:      [sha256.Size]byte{1, 2, 3, 4},
		Timestamp:  12345,
		Extensions: []byte{1, 2, 3},
		Signature: DigitallySigned{
			Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
			Signature: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		},
	}

	resp, err := ToAddChainResponse(sct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.SCTVersion != sct.SCTVersion {
		t.Fatalf("SCTVersion = %d, want %d", resp.SCTVersion, sct.SCTVersion)
	}
	if !bytes.Equal(resp.ID, sct.LogID[:]) {
		t.Fatal("ID does not match")
	}
	if resp.Timestamp != sct.Timestamp {
		t.Fatalf("Timestamp = %d, want %d", resp.Timestamp, sct.Timestamp)
	}
	if resp.Extensions != base64.StdEncoding.EncodeToString(sct.Extensions) {
		t.Fatalf("Extensions = %q, want %q", resp.Extensions, base64.StdEncoding.EncodeToString(sct.Extensions))
	}
	sig, err := sct.Signature.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS() = %v", err)
	}
	if !bytes.Equal(resp.Signature, sig) {
		t.Fatal("Signature does not match")
	}

	// Oversized signature must fail.
	bad := *sct
	bad.Signature.Signature = make([]byte, 65536)
	if _, err := ToAddChainResponse(&bad); err == nil {
		t.Fatal("expected error for oversized signature")
	}
}

func TestDigitallySignedRoundTrip(t *testing.T) {
	want := DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
		Signature: []byte{1, 2, 3, 4, 5},
	}
	raw, err := want.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS() = %v", err)
	}
	wantHex := "040300050102030405"
	if gotHex := hex.EncodeToString(raw); gotHex != wantHex {
		t.Fatalf("MarshalTLS() = %s, want %s", gotHex, wantHex)
	}
	got, err := UnmarshalDigitallySigned(raw)
	if err != nil {
		t.Fatalf("UnmarshalDigitallySigned() = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	// Trailing bytes must fail.
	if _, err := UnmarshalDigitallySigned(append(raw, 0x00)); err == nil {
		t.Fatal("expected error for trailing data")
	}
	// Truncated inputs must fail.
	for _, trunc := range [][]byte{{}, {0x04}, {0x04, 0x03}, {0x04, 0x03, 0x00, 0x05, 0x01}} {
		if _, err := UnmarshalDigitallySigned(trunc); err == nil {
			t.Fatalf("expected error for truncated DigitallySigned %x", trunc)
		}
	}
	// Signature > 65535 bytes must fail.
	oversized := DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
		Signature: make([]byte, 65536),
	}
	if _, err := oversized.MarshalTLS(); err == nil {
		t.Fatal("expected error for signature exceeding max uint16")
	}
}

func TestRFC6962WireFormatGoldenVectors(t *testing.T) {
	var logID [sha256.Size]byte
	copy(logID[:], "iamapublickeyshatwofivesixdigest")

	// RFC 6962 s3.2 SignedCertificateTimestamp wire layout:
	//   version(1) || log_id(32) || timestamp(8) || extensions_len(2) || extensions ||
	//   hash_alg(1) || sig_alg(1) || sig_len(2) || sig
	sct := SignedCertificateTimestamp{
		SCTVersion: V1,
		LogID:      logID,
		Timestamp:  1234, // 0x00000000000004d2
		Extensions: nil,
		Signature: DigitallySigned{
			Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
			Signature: []byte("signature"),
		},
	}
	wantSCTHex := "00" +
		"69616d617075626c69636b657973686174776f66697665736978646967657374" +
		"00000000000004d2" +
		"0000" +
		"0403" +
		"0009" +
		"7369676e6174757265"
	gotSCT, err := sct.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS() = %v", err)
	}
	if gotHex := hex.EncodeToString(gotSCT); gotHex != wantSCTHex {
		t.Fatalf("SCT MarshalTLS() =\n%s\nwant:\n%s", gotHex, wantSCTHex)
	}

	// RFC 6962 s3.3 SignedCertificateTimestampList with two SCTs (second has extensions).
	sct2 := sct
	sct2.Timestamp = 5678 // 0x000000000000162e
	sct2.Extensions = []byte{0xde, 0xad}
	wantSCT2Hex := "00" +
		"69616d617075626c69636b657973686174776f66697665736978646967657374" +
		"000000000000162e" +
		"0002dead" +
		"0403" +
		"0009" +
		"7369676e6174757265"
	// sct is 56 bytes (0x0038), sct2 is 58 bytes (0x003a); total inner = (2+56)+(2+58) = 118 (0x0076)
	wantListHex := "0076" + "0038" + wantSCTHex + "003a" + wantSCT2Hex
	gotList, err := MarshalSCTList([]SignedCertificateTimestamp{sct, sct2})
	if err != nil {
		t.Fatalf("MarshalSCTList() = %v", err)
	}
	if gotHex := hex.EncodeToString(gotList); gotHex != wantListHex {
		t.Fatalf("MarshalSCTList() =\n%s\nwant:\n%s", gotHex, wantListHex)
	}

	// RFC 6962 s3.2 CertificateTimestamp signature input for x509_entry:
	//   version(1) || sig_type(1) || timestamp(8) || entry_type(2) ||
	//   cert_len(3) || cert || extensions_len(2) || extensions
	wantX509InputHex := "00" +
		"00" +
		"00000000000004d2" +
		"0000" +
		"00000b" +
		"6365727469666963617465" + // "certificate"
		"0002" +
		"cafe"
	sctWithExt := sct
	sctWithExt.Extensions = []byte{0xca, 0xfe}
	gotX509Input, err := serializeSCTSignatureInput(sctWithExt, X509LogEntryType, [][]byte{[]byte("certificate")})
	if err != nil {
		t.Fatalf("serializeSCTSignatureInput(X509) = %v", err)
	}
	if gotHex := hex.EncodeToString(gotX509Input); gotHex != wantX509InputHex {
		t.Fatalf("serializeSCTSignatureInput(X509) =\n%s\nwant:\n%s", gotHex, wantX509InputHex)
	}
}

func TestMarshalSCTListErrors(t *testing.T) {
	if _, err := MarshalSCTList(nil); err == nil {
		t.Fatal("expected error for empty SCT list")
	}

	oversizedExt := SignedCertificateTimestamp{
		SCTVersion: V1,
		Extensions: make([]byte, 65536),
	}
	if _, err := oversizedExt.MarshalTLS(); err == nil {
		t.Fatal("expected error for extensions exceeding max uint16")
	}
	if _, err := MarshalSCTList([]SignedCertificateTimestamp{oversizedExt}); err == nil {
		t.Fatal("expected error from MarshalSCTList for oversized extensions")
	}
}

func TestParsePublicKeyPEMAndNewSignatureVerifier(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})

	pk, err := ParsePublicKeyPEM(ecPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM(ECDSA P-256) = %v", err)
	}
	if _, err := NewSignatureVerifier(pk); err != nil {
		t.Fatalf("NewSignatureVerifier(ECDSA P-256) = %v", err)
	}

	// Trailing data rejected
	if _, err := ParsePublicKeyPEM(append(ecPEM, []byte("extra")...)); err == nil {
		t.Fatal("expected error for trailing PEM data")
	}
	// No PEM block rejected
	if _, err := ParsePublicKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for non-PEM data")
	}

	// P-384 rejected per RFC 6962
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignatureVerifier(&p384Key.PublicKey); err == nil {
		t.Fatal("expected error for ECDSA P-384")
	}

	// RSA 1024 rejected per RFC 6962 (< 2048 bits)
	rsa1024Key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignatureVerifier(&rsa1024Key.PublicKey); err == nil {
		t.Fatal("expected error for RSA 1024")
	}

	// RSA 2048 accepted
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignatureVerifier(&rsaKey.PublicKey); err != nil {
		t.Fatalf("NewSignatureVerifier(RSA 2048) = %v", err)
	}

	// Ed25519 rejected per RFC 6962
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignatureVerifier(edPub); err == nil {
		t.Fatal("expected error for Ed25519")
	}
}

// independentSCTSignatureInput constructs the RFC 6962 section 3.2
// digitally-signed CertificateTimestamp struct directly from the RFC wire
// specification, without calling serializeSCTSignatureInput or buildPrecertTBS.
func independentSCTSignatureInput(entryType LogEntryType, ts uint64, leafDERorFinalTBS []byte, issuerSPKI []byte, exts []byte) []byte {
	var buf bytes.Buffer
	// sct_version = v1 (0), signature_type = certificate_timestamp (0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	// uint64 timestamp (big-endian)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], ts)
	buf.Write(u64[:])
	// LogEntryType entry_type (uint16 big-endian)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(entryType))
	buf.Write(u16[:])

	if entryType == PrecertLogEntryType {
		// opaque issuer_key_hash[32]
		issuerHash := sha256.Sum256(issuerSPKI)
		buf.Write(issuerHash[:])
	}
	// opaque ASN.1Cert<1..2^24-1> or opaque tbs_certificate<1..2^24-1>
	n := len(leafDERorFinalTBS)
	buf.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	buf.Write(leafDERorFinalTBS)

	// opaque CtExtensions<0..2^16-1>
	binary.BigEndian.PutUint16(u16[:], uint16(len(exts)))
	buf.Write(u16[:])
	buf.Write(exts)
	return buf.Bytes()
}

// makeMatchedCertPair creates a CA cert, a final leaf cert (without CT poison),
// and a precertificate (with identical TBS fields plus the CT poison extension).
// Per RFC 6962 s3.1, stripping the poison extension from precert must match
// finalCert.RawTBSCertificate byte-for-byte.
func makeMatchedCertPair(t *testing.T) (precert, finalCert, caCert *x509.Certificate) {
	t.Helper()
	now := time.Now().Truncate(time.Second)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseTmpl := x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "Test Leaf"},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SubjectKeyId:   []byte{0xaa, 0xbb, 0xcc, 0xdd},
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	finalTmpl := baseTmpl
	finalDER, err := x509.CreateCertificate(rand.Reader, &finalTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	finalCert, err = x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatal(err)
	}

	preTmpl := baseTmpl
	preTmpl.ExtraExtensions = []pkix.Extension{{
		Id:       OIDExtensionCTPoison,
		Critical: true,
		Value:    asn1.NullBytes,
	}}
	preDER, err := x509.CreateCertificate(rand.Reader, &preTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	precert, err = x509.ParseCertificate(preDER)
	if err != nil {
		t.Fatal(err)
	}
	return precert, finalCert, caCert
}

// makePreIssuerCertChain creates a 3-cert precertificate chain using a dedicated
// CT Precertificate Signing CA (RFC 6962 s3.1) with the CT EKU, alongside the
// equivalent final certificate signed directly by rootCA.
func makePreIssuerCertChain(t *testing.T, preIssuerHasAKI, precertHasAKI bool) (precert, preIssuer, rootCA, finalCert *x509.Certificate) {
	t.Helper()
	now := time.Now().Truncate(time.Second)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootSKI := []byte{0x10, 0x20, 0x30, 0x40}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Real Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if preIssuerHasAKI {
		rootTmpl.SubjectKeyId = rootSKI
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	preIssuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	preIssuerSKI := []byte{0x50, 0x60, 0x70, 0x80}
	preIssuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Precert Signing CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDExtKeyUsageCertificateTransparency},
	}
	if precertHasAKI {
		preIssuerTmpl.SubjectKeyId = preIssuerSKI
	}
	if preIssuerHasAKI {
		preIssuerTmpl.AuthorityKeyId = rootSKI
	}
	preIssuerDER, err := x509.CreateCertificate(rand.Reader, preIssuerTmpl, rootCA, &preIssuerKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	preIssuer, err = x509.ParseCertificate(preIssuerDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseLeaf := x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "PreIssuer Leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	// Final cert signed directly by rootCA.
	finalTmpl := baseLeaf
	if preIssuerHasAKI {
		finalTmpl.AuthorityKeyId = rootSKI
	}
	finalDER, err := x509.CreateCertificate(rand.Reader, &finalTmpl, rootCA, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	finalCert, err = x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatal(err)
	}

	// Precert signed by preIssuer with CT poison extension.
	preTmpl := baseLeaf
	if precertHasAKI {
		preTmpl.AuthorityKeyId = preIssuerSKI
	}
	preTmpl.ExtraExtensions = []pkix.Extension{{
		Id:       OIDExtensionCTPoison,
		Critical: true,
		Value:    asn1.NullBytes,
	}}
	preDER, err := x509.CreateCertificate(rand.Reader, &preTmpl, preIssuer, &leafKey.PublicKey, preIssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	precert, err = x509.ParseCertificate(preDER)
	if err != nil {
		t.Fatal(err)
	}

	return precert, preIssuer, rootCA, finalCert
}

// signIndependentSCT signs an SCT using independentSCTSignatureInput (not the
// package's serializeSCTSignatureInput) so verification tests are non-circular.
func signIndependentSCT(t *testing.T, logSigner crypto.Signer, entryType LogEntryType, leafDERorFinalTBS, issuerSPKI []byte, ts uint64, exts []byte) AddChainResponse {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(logSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	logID := sha256.Sum256(pubDER)

	sigInput := independentSCTSignatureInput(entryType, ts, leafDERorFinalTBS, issuerSPKI, exts)
	digest := sha256.Sum256(sigInput)

	hashAlg := byte(SHA256)
	var sigAlg byte
	var sigBytes []byte
	switch k := logSigner.(type) {
	case *ecdsa.PrivateKey:
		sigAlg = byte(ECDSA)
		sigBytes, err = ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	case *rsa.PrivateKey:
		sigAlg = byte(RSA)
		sigBytes, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported signer %T", logSigner)
	}

	// Independently encode TLS DigitallySigned: hash(1) || sigAlg(1) || len(2) || sig.
	rawSig := make([]byte, 4+len(sigBytes))
	rawSig[0] = hashAlg
	rawSig[1] = sigAlg
	binary.BigEndian.PutUint16(rawSig[2:4], uint16(len(sigBytes)))
	copy(rawSig[4:], sigBytes)

	return AddChainResponse{
		SCTVersion: V1,
		ID:         logID[:],
		Timestamp:  ts,
		Extensions: base64.StdEncoding.EncodeToString(exts),
		Signature:  rawSig,
	}
}

func TestClientAddChainAndAddPreChainWithVerification(t *testing.T) {
	ecLogKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaLogKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		logKey    crypto.Signer
		precert   bool
		preIssuer bool
		exts      []byte
		tamperSig bool
		wantErr   bool
	}{
		{name: "add-chain ECDSA valid", logKey: ecLogKey},
		{name: "add-chain ECDSA with extensions", logKey: ecLogKey, exts: []byte{0x01, 0x02, 0x03}},
		{name: "add-chain ECDSA tampered signature", logKey: ecLogKey, tamperSig: true, wantErr: true},
		{name: "add-pre-chain ECDSA valid", logKey: ecLogKey, precert: true},
		{name: "add-pre-chain ECDSA with extensions", logKey: ecLogKey, precert: true, exts: []byte{0xaa, 0xbb}},
		{name: "add-pre-chain ECDSA with dedicated pre-issuer", logKey: ecLogKey, precert: true, preIssuer: true},
		{name: "add-chain RSA valid", logKey: rsaLogKey},
		{name: "add-chain RSA tampered signature", logKey: rsaLogKey, tamperSig: true, wantErr: true},
		{name: "add-pre-chain RSA valid", logKey: rsaLogKey, precert: true},
		{name: "add-pre-chain RSA with dedicated pre-issuer", logKey: rsaLogKey, precert: true, preIssuer: true},
		{name: "add-pre-chain tampered signature", logKey: ecLogKey, precert: true, tamperSig: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var chain [][]byte
			var leafDERorFinalTBS []byte
			var issuerSPKI []byte

			if tc.preIssuer {
				precert, preIssuerCert, rootCA, finalCert := makePreIssuerCertChain(t, true, true)
				chain = BuildCTChain(precert, []*x509.Certificate{preIssuerCert, rootCA})
				leafDERorFinalTBS = finalCert.RawTBSCertificate
				issuerSPKI = rootCA.RawSubjectPublicKeyInfo
			} else {
				precert, finalCert, caCert := makeMatchedCertPair(t)
				if tc.precert {
					chain = BuildCTChain(precert, []*x509.Certificate{caCert})
					leafDERorFinalTBS = finalCert.RawTBSCertificate
					issuerSPKI = caCert.RawSubjectPublicKeyInfo
				} else {
					chain = BuildCTChain(finalCert, []*x509.Certificate{caCert})
					leafDERorFinalTBS = finalCert.Raw
				}
			}

			pubDER, err := x509.MarshalPKIXPublicKey(tc.logKey.Public())
			if err != nil {
				t.Fatal(err)
			}
			pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := AddChainPath
				entryType := X509LogEntryType
				if tc.precert {
					wantPath = AddPreChainPath
					entryType = PrecertLogEntryType
				}
				if r.URL.Path != wantPath {
					t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
				}
				var req AddChainRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if !reflect.DeepEqual(req.Chain, chain) {
					t.Errorf("submitted chain did not match expected chain")
				}
				resp := signIndependentSCT(t, tc.logKey, entryType, leafDERorFinalTBS, issuerSPKI, 1700000000000, tc.exts)
				if tc.tamperSig {
					resp.Signature[len(resp.Signature)-1] ^= 0xff
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()

			// Include trailing slash to verify URI trimming.
			client, err := NewClient(srv.URL+"/", srv.Client(), Options{PublicKey: pubPEM, Logger: noopLogger{}})
			if err != nil {
				t.Fatalf("NewClient() = %v", err)
			}

			var sct *SignedCertificateTimestamp
			if tc.precert {
				sct, err = client.AddPreChain(context.Background(), chain)
			} else {
				sct, err = client.AddChain(context.Background(), chain)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if _, ok := errors.AsType[RspError](err); !ok {
					t.Fatalf("expected RspError, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sct.Timestamp != 1700000000000 {
				t.Fatalf("Timestamp = %d, want 1700000000000", sct.Timestamp)
			}
			if !bytes.Equal(sct.Extensions, tc.exts) {
				t.Fatalf("Extensions = %x, want %x", sct.Extensions, tc.exts)
			}
		})
	}
}

func TestVerifyDigitallySignedAndSerializeErrors(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecVerifier, err := NewSignatureVerifier(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaVerifier, err := NewSignatureVerifier(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("signed payload")

	// Valid SHA-384 and SHA-512 verification paths.
	for _, tc := range []struct {
		name string
		alg  HashAlgorithm
		hash crypto.Hash
	}{
		{"SHA384", SHA384, crypto.SHA384},
		{"SHA512", SHA512, crypto.SHA512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.hash.New()
			_, _ = h.Write(data)
			digest := h.Sum(nil)
			sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest)
			if err != nil {
				t.Fatal(err)
			}
			ds := DigitallySigned{
				Algorithm: SignatureAndHashAlgorithm{Hash: tc.alg, Signature: ECDSA},
				Signature: sig,
			}
			if err := verifyDigitallySigned(&ecKey.PublicKey, data, ds); err != nil {
				t.Fatalf("verifyDigitallySigned(%s) = %v", tc.name, err)
			}
		})
	}

	// Mismatched key type vs signature algorithm.
	if err := verifyDigitallySigned(&ecKey.PublicKey, data, DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: RSA},
	}); err == nil {
		t.Fatal("expected error verifying RSA signature with ECDSA key")
	}
	if err := verifyDigitallySigned(&rsaKey.PublicKey, data, DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
	}); err == nil {
		t.Fatal("expected error verifying ECDSA signature with RSA key")
	}

	// Unsupported hash and signature algorithms.
	if err := verifyDigitallySigned(&ecKey.PublicKey, data, DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: HashNone, Signature: ECDSA},
	}); err == nil {
		t.Fatal("expected error for HashNone")
	}
	if err := verifyDigitallySigned(&ecKey.PublicKey, data, DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: DSA},
	}); err == nil {
		t.Fatal("expected error for DSA signature algorithm")
	}
	if err := verifyDigitallySigned(&ecKey.PublicKey, data, DigitallySigned{
		Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: Anonymous},
	}); err == nil {
		t.Fatal("expected error for Anonymous signature algorithm")
	}

	// serializeSCTSignatureInput validation errors.
	precert, preIssuer, _, _ := makePreIssuerCertChain(t, true, true)
	for _, tc := range []struct {
		name      string
		sct       SignedCertificateTimestamp
		entryType LogEntryType
		chain     [][]byte
	}{
		{
			name:      "unknown SCT version",
			sct:       SignedCertificateTimestamp{SCTVersion: Version(1)},
			entryType: X509LogEntryType,
			chain:     [][]byte{precert.Raw},
		},
		{
			name:      "empty chain",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: X509LogEntryType,
			chain:     nil,
		},
		{
			name:      "precert missing issuer",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: PrecertLogEntryType,
			chain:     [][]byte{precert.Raw},
		},
		{
			name:      "pre-issuer missing final issuer",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: PrecertLogEntryType,
			chain:     [][]byte{precert.Raw, preIssuer.Raw},
		},
		{
			name:      "unsupported entry type",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: LogEntryType(99),
			chain:     [][]byte{precert.Raw},
		},
		{
			name:      "unparseable precert leaf",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: PrecertLogEntryType,
			chain:     [][]byte{[]byte("not-der"), preIssuer.Raw},
		},
		{
			name:      "unparseable precert issuer",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: PrecertLogEntryType,
			chain:     [][]byte{precert.Raw, []byte("not-der")},
		},
		{
			name:      "unparseable pre-issuer final issuer",
			sct:       SignedCertificateTimestamp{SCTVersion: V1},
			entryType: PrecertLogEntryType,
			chain:     [][]byte{precert.Raw, preIssuer.Raw, []byte("not-der")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ecVerifier.VerifySCTSignature(tc.sct, tc.entryType, tc.chain); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			_ = rsaVerifier
		})
	}
}

func TestBuildPrecertTBS(t *testing.T) {
	t.Run("removes poison and matches final cert TBS byte-for-byte", func(t *testing.T) {
		precert, finalCert, _ := makeMatchedCertPair(t)
		defanged, err := buildPrecertTBS(precert.RawTBSCertificate, nil)
		if err != nil {
			t.Fatalf("buildPrecertTBS() = %v", err)
		}
		if !bytes.Equal(defanged, finalCert.RawTBSCertificate) {
			t.Fatalf("defanged TBS does not match final cert TBS byte-for-byte:\ngot:  %x\nwant: %x", defanged, finalCert.RawTBSCertificate)
		}
	})

	t.Run("pre-issuer with AKI replaces issuer and AKI to match final cert TBS byte-for-byte", func(t *testing.T) {
		precert, preIssuer, _, finalCert := makePreIssuerCertChain(t, true, true)
		defanged, err := buildPrecertTBS(precert.RawTBSCertificate, preIssuer)
		if err != nil {
			t.Fatalf("buildPrecertTBS() = %v", err)
		}
		if !bytes.Equal(defanged, finalCert.RawTBSCertificate) {
			t.Fatalf("defanged TBS with pre-issuer does not match final cert TBS byte-for-byte:\ngot:  %x\nwant: %x", defanged, finalCert.RawTBSCertificate)
		}
	})

	t.Run("pre-issuer without AKI removes precert AKI and matches final cert TBS", func(t *testing.T) {
		precert, preIssuer, _, finalCert := makePreIssuerCertChain(t, false, true)
		defanged, err := buildPrecertTBS(precert.RawTBSCertificate, preIssuer)
		if err != nil {
			t.Fatalf("buildPrecertTBS() = %v", err)
		}
		if !bytes.Equal(defanged, finalCert.RawTBSCertificate) {
			t.Fatalf("defanged TBS does not match final cert TBS:\ngot:  %x\nwant: %x", defanged, finalCert.RawTBSCertificate)
		}
	})

	t.Run("pre-issuer with AKI appends AKI when precert lacks AKI", func(t *testing.T) {
		precert, preIssuer, _, _ := makePreIssuerCertChain(t, true, false)
		defanged, err := buildPrecertTBS(precert.RawTBSCertificate, preIssuer)
		if err != nil {
			t.Fatalf("buildPrecertTBS() = %v", err)
		}
		// Extract preIssuer's AKI value and verify it was appended to defanged TBS.
		var wantAKI []byte
		for _, ext := range preIssuer.Extensions {
			if ext.Id.Equal(OIDExtensionAuthorityKeyID) {
				wantAKI = ext.Value
				break
			}
		}
		if wantAKI == nil {
			t.Fatal("expected preIssuer to have AKI")
		}
		if !bytes.Contains(defanged, wantAKI) {
			t.Fatalf("expected defanged TBS to contain preIssuer AKI %x", wantAKI)
		}
		if !bytes.Contains(defanged, preIssuer.RawIssuer) {
			t.Fatal("expected defanged TBS to contain preIssuer.RawIssuer")
		}
	})

	t.Run("pre-issuer without AKI and precert without AKI matches final cert TBS", func(t *testing.T) {
		precert, preIssuer, _, finalCert := makePreIssuerCertChain(t, false, false)
		defanged, err := buildPrecertTBS(precert.RawTBSCertificate, preIssuer)
		if err != nil {
			t.Fatalf("buildPrecertTBS() = %v", err)
		}
		if !bytes.Equal(defanged, finalCert.RawTBSCertificate) {
			t.Fatalf("defanged TBS does not match final cert TBS:\ngot:  %x\nwant: %x", defanged, finalCert.RawTBSCertificate)
		}
	})

	t.Run("preserves issuerUniqueID and subjectUniqueID and omits empty extensions", func(t *testing.T) {
		// Build a synthetic DER TBSCertificate with optional [1] issuerUniqueID,
		// [2] subjectUniqueID, and poison as the ONLY extension.
		buildSynthTBS := func(includePoison bool, poisonCount int) []byte {
			var b cryptobyte.Builder
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// version [0] EXPLICIT INTEGER 2 (v3)
				b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1Int64(2)
				})
				b.AddASN1Int64(42)                                                                // serialNumber
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(_ *cryptobyte.Builder) {})               // signature
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(_ *cryptobyte.Builder) {})               // issuer
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(_ *cryptobyte.Builder) {})               // validity
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(_ *cryptobyte.Builder) {})               // subject
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(_ *cryptobyte.Builder) {})               // spki
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) { // issuerUniqueID
					b.AddBytes([]byte{0x00, 0xaa, 0xbb})
				})
				b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) { // subjectUniqueID
					b.AddBytes([]byte{0x00, 0xcc, 0xdd})
				})
				if includePoison {
					b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							for range poisonCount {
								b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
									b.AddASN1ObjectIdentifier(OIDExtensionCTPoison)
									b.AddASN1Boolean(true)
									b.AddASN1OctetString(asn1.NullBytes)
								})
							}
						})
					})
				}
			})
			out, err := b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			return out
		}

		withOnePoison := buildSynthTBS(true, 1)
		wantWithoutExts := buildSynthTBS(false, 0)
		got, err := buildPrecertTBS(withOnePoison, nil)
		if err != nil {
			t.Fatalf("buildPrecertTBS(only poison) = %v", err)
		}
		if !bytes.Equal(got, wantWithoutExts) {
			t.Fatalf("got %x, want %x", got, wantWithoutExts)
		}

		// Two poison extensions must fail.
		withTwoPoisons := buildSynthTBS(true, 2)
		if _, err := buildPrecertTBS(withTwoPoisons, nil); err == nil || !strings.Contains(err.Error(), "multiple extensions") {
			t.Fatalf("expected multiple extensions error, got %v", err)
		}

		// No [3] extensions at all must fail.
		if _, err := buildPrecertTBS(wantWithoutExts, nil); err == nil {
			t.Fatal("expected error when extensions block is absent")
		}

		// Trailing data after TBSCertificate must fail.
		if _, err := buildPrecertTBS(append(withOnePoison, 0x01, 0x02), nil); err == nil {
			t.Fatal("expected error for trailing data after TBSCertificate")
		}
	})

	t.Run("non-precert without poison extension fails", func(t *testing.T) {
		_, finalCert, _ := makeMatchedCertPair(t)
		if _, err := buildPrecertTBS(finalCert.RawTBSCertificate, nil); err == nil {
			t.Fatal("expected error when poison extension is missing")
		}
	})
}

func TestBackoff(t *testing.T) {
	b := &backoff{}

	// Exponential progression: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, capped at 128s.
	wantWaits := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		64 * time.Second,
		128 * time.Second,
		128 * time.Second, // capped at 2^(maxMultiplier-1)
	}
	for i, want := range wantWaits {
		// Expire previous notBefore without sleeping.
		b.notBefore = time.Now().Add(-time.Second)
		if got := b.set(nil); got != want {
			t.Fatalf("step %d: backoff.set(nil) = %v, want %v", i, got, want)
		}
	}

	// While notBefore is in the future, nil or shorter override must not shorten it.
	b2 := &backoff{}
	initial := 10 * time.Second
	if got := b2.set(&initial); got != initial {
		t.Fatalf("set(&10s) = %v, want 10s", got)
	}
	firstUntil := b2.until()

	shorter := 2 * time.Second
	b2.set(&shorter)
	if !b2.until().Equal(firstUntil) {
		t.Fatalf("shorter override modified notBefore: got %v, want %v", b2.until(), firstUntil)
	}

	// Longer override while notBefore is in the future must extend it.
	longer := 30 * time.Second
	b2.set(&longer)
	if !b2.until().After(firstUntil) {
		t.Fatalf("longer override did not extend notBefore: got %v, prev %v", b2.until(), firstUntil)
	}
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient("http://example.com", nil, Options{PublicKey: "not a pem"}); err == nil {
		t.Fatal("expected error for invalid PEM public key")
	}

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p384DER}))
	if _, err := NewClient("http://example.com", nil, Options{PublicKey: p384PEM}); err == nil {
		t.Fatal("expected error for unsupported ECDSA P-384 key")
	}

	c, err := NewClient("http://example.com///", nil, Options{})
	if err != nil {
		t.Fatalf("NewClient() = %v", err)
	}
	if c.uri != "http://example.com" {
		t.Fatalf("uri = %q, want %q", c.uri, "http://example.com")
	}
	if c.httpClient == nil || c.logger == nil {
		t.Fatal("expected default httpClient and logger when nil")
	}
}

func TestClientRetryAndErrors(t *testing.T) {
	const validSCTJSON = `{
		"sct_version":0,
		"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=",
		"timestamp":1337,
		"extensions":"",
		"signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="
	}`

	t.Run("nil context rejected", func(t *testing.T) {
		client, err := NewClient("http://127.0.0.1:1", nil, Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		//nolint:staticcheck // intentionally testing nil context guard
		if _, err := client.AddChain(nil, [][]byte{[]byte("cert")}); err == nil {
			t.Fatal("expected error for nil context")
		}
	})

	t.Run("non-retryable 400 returns RspError with body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid cert chain"))
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.AddChain(context.Background(), [][]byte{[]byte("bad")})
		rspErr, ok := errors.AsType[RspError](err)
		if !ok {
			t.Fatalf("expected RspError, got %T: %v", err, err)
		}
		if rspErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("StatusCode = %d, want 400", rspErr.StatusCode)
		}
		if string(rspErr.Body) != "invalid cert chain" {
			t.Fatalf("Body = %q, want %q", string(rspErr.Body), "invalid cert chain")
		}
	})

	t.Run("retries on 408, 503 with Retry-After seconds, and 429 with Retry-After RFC1123 date", func(t *testing.T) {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := attempts.Add(1)
			switch n {
			case 1:
				w.WriteHeader(http.StatusRequestTimeout)
				return
			case 2:
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case 3:
				w.Header().Set("Retry-After", time.Now().UTC().Add(-time.Second).Format(time.RFC1123))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			default:
				_, _ = w.Write([]byte(validSCTJSON))
			}
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		sct, err := client.AddChain(context.Background(), [][]byte{[]byte("cert")})
		if err != nil {
			t.Fatalf("AddChain() = %v", err)
		}
		if sct.Timestamp != 1337 {
			t.Fatalf("Timestamp = %d, want 1337", sct.Timestamp)
		}
		if attempts.Load() != 4 {
			t.Fatalf("attempts = %d, want 4", attempts.Load())
		}
	})

	t.Run("context cancellation stops retries", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err = client.AddChain(ctx, [][]byte{[]byte("cert")})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("503 without Retry-After uses exponential backoff", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err = client.AddChain(ctx, [][]byte{[]byte("cert")})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("POST redirected to GET fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				http.Redirect(w, r, "/redirected", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(validSCTJSON))
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err = client.AddChain(ctx, [][]byte{[]byte("cert")})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded after redirect failure, got %v", err)
		}
	})

	t.Run("malformed JSON on 200 retries until context deadline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{not valid json"))
		}))
		defer srv.Close()

		client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err = client.AddChain(ctx, [][]byte{[]byte("cert")})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "invalid log ID length",
			body: `{"sct_version":0,"id":"AAAA","timestamp":1337,"extensions":"","signature":"BAMAAwECAw=="}`,
		},
		{
			name: "invalid base64 extensions",
			body: `{"sct_version":0,"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=","timestamp":1337,"extensions":"!!!not-base64!!!","signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="}`,
		},
		{
			name: "truncated DigitallySigned signature",
			body: `{"sct_version":0,"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=","timestamp":1337,"extensions":"","signature":"BAM="}`,
		},
		{
			name: "trailing bytes in DigitallySigned signature",
			body: `{"sct_version":0,"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=","timestamp":1337,"extensions":"","signature":"BAMAAQAA"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			client, err := NewClient(srv.URL, srv.Client(), Options{Logger: noopLogger{}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = client.AddChain(ctx, [][]byte{[]byte("cert")})
			rspErr, ok := errors.AsType[RspError](err)
			if !ok {
				t.Fatalf("expected RspError, got %T: %v", err, err)
			}
			if rspErr.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode = %d, want 200", rspErr.StatusCode)
			}
			if string(rspErr.Body) != tc.body {
				t.Fatalf("Body = %q, want %q", string(rspErr.Body), tc.body)
			}
		})
	}
}
