//
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v6.30.2
// source: fulcio.proto

package protobuf

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PublicKeyAlgorithm int32

const (
	PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED PublicKeyAlgorithm = 0
	PublicKeyAlgorithm_RSA_PSS                          PublicKeyAlgorithm = 1
	PublicKeyAlgorithm_ECDSA                            PublicKeyAlgorithm = 2
	PublicKeyAlgorithm_ED25519                          PublicKeyAlgorithm = 3
)

// Enum value maps for PublicKeyAlgorithm.
var (
	PublicKeyAlgorithm_name = map[int32]string{
		0: "PUBLIC_KEY_ALGORITHM_UNSPECIFIED",
		1: "RSA_PSS",
		2: "ECDSA",
		3: "ED25519",
	}
	PublicKeyAlgorithm_value = map[string]int32{
		"PUBLIC_KEY_ALGORITHM_UNSPECIFIED": 0,
		"RSA_PSS":                          1,
		"ECDSA":                            2,
		"ED25519":                          3,
	}
)

func (x PublicKeyAlgorithm) Enum() *PublicKeyAlgorithm {
	p := new(PublicKeyAlgorithm)
	*p = x
	return p
}

func (x PublicKeyAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PublicKeyAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_fulcio_proto_enumTypes[0].Descriptor()
}

func (PublicKeyAlgorithm) Type() protoreflect.EnumType {
	return &file_fulcio_proto_enumTypes[0]
}

func (x PublicKeyAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PublicKeyAlgorithm.Descriptor instead.
func (PublicKeyAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{0}
}

type CreateSigningCertificateRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Identity information about who possesses the private / public key pair presented
	Credentials *Credentials `protobuf:"bytes,1,opt,name=credentials,proto3" json:"credentials,omitempty"`
	// Types that are valid to be assigned to Key:
	//
	//	*CreateSigningCertificateRequest_PublicKeyRequest
	//	*CreateSigningCertificateRequest_CertificateSigningRequest
	Key           isCreateSigningCertificateRequest_Key `protobuf_oneof:"key"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CreateSigningCertificateRequest) Reset() {
	*x = CreateSigningCertificateRequest{}
	mi := &file_fulcio_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CreateSigningCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSigningCertificateRequest) ProtoMessage() {}

func (x *CreateSigningCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSigningCertificateRequest.ProtoReflect.Descriptor instead.
func (*CreateSigningCertificateRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{0}
}

func (x *CreateSigningCertificateRequest) GetCredentials() *Credentials {
	if x != nil {
		return x.Credentials
	}
	return nil
}

func (x *CreateSigningCertificateRequest) GetKey() isCreateSigningCertificateRequest_Key {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *CreateSigningCertificateRequest) GetPublicKeyRequest() *PublicKeyRequest {
	if x != nil {
		if x, ok := x.Key.(*CreateSigningCertificateRequest_PublicKeyRequest); ok {
			return x.PublicKeyRequest
		}
	}
	return nil
}

func (x *CreateSigningCertificateRequest) GetCertificateSigningRequest() []byte {
	if x != nil {
		if x, ok := x.Key.(*CreateSigningCertificateRequest_CertificateSigningRequest); ok {
			return x.CertificateSigningRequest
		}
	}
	return nil
}

type isCreateSigningCertificateRequest_Key interface {
	isCreateSigningCertificateRequest_Key()
}

type CreateSigningCertificateRequest_PublicKeyRequest struct {
	// The public key to be stored in the requested certificate along with a signed
	// challenge as proof of possession of the private key.
	PublicKeyRequest *PublicKeyRequest `protobuf:"bytes,2,opt,name=public_key_request,json=publicKeyRequest,proto3,oneof"`
}

type CreateSigningCertificateRequest_CertificateSigningRequest struct {
	// PKCS#10 PEM-encoded certificate signing request
	//
	// Contains the public key to be stored in the requested certificate. All other CSR fields
	// are ignored. Since the CSR is self-signed, it also acts as a proof of possession of
	// the private key.
	//
	// In particular, the CSR's subject name is not verified, or tested for
	// compatibility with its specified X.509 name type (e.g. email address).
	CertificateSigningRequest []byte `protobuf:"bytes,3,opt,name=certificate_signing_request,json=certificateSigningRequest,proto3,oneof"`
}

func (*CreateSigningCertificateRequest_PublicKeyRequest) isCreateSigningCertificateRequest_Key() {}

func (*CreateSigningCertificateRequest_CertificateSigningRequest) isCreateSigningCertificateRequest_Key() {
}

type Credentials struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Credentials:
	//
	//	*Credentials_OidcIdentityToken
	Credentials   isCredentials_Credentials `protobuf_oneof:"credentials"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Credentials) Reset() {
	*x = Credentials{}
	mi := &file_fulcio_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Credentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credentials) ProtoMessage() {}

func (x *Credentials) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credentials.ProtoReflect.Descriptor instead.
func (*Credentials) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{1}
}

func (x *Credentials) GetCredentials() isCredentials_Credentials {
	if x != nil {
		return x.Credentials
	}
	return nil
}

func (x *Credentials) GetOidcIdentityToken() string {
	if x != nil {
		if x, ok := x.Credentials.(*Credentials_OidcIdentityToken); ok {
			return x.OidcIdentityToken
		}
	}
	return ""
}

type isCredentials_Credentials interface {
	isCredentials_Credentials()
}

type Credentials_OidcIdentityToken struct {
	// The OIDC token that identifies the caller
	OidcIdentityToken string `protobuf:"bytes,1,opt,name=oidc_identity_token,json=oidcIdentityToken,proto3,oneof"`
}

func (*Credentials_OidcIdentityToken) isCredentials_Credentials() {}

type PublicKeyRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The public key to be stored in the requested certificate
	PublicKey *PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// Proof that the client possesses the private key; must be verifiable by provided public key
	//
	// This is a currently a signature over the `sub` claim from the OIDC identity token
	ProofOfPossession []byte `protobuf:"bytes,2,opt,name=proof_of_possession,json=proofOfPossession,proto3" json:"proof_of_possession,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *PublicKeyRequest) Reset() {
	*x = PublicKeyRequest{}
	mi := &file_fulcio_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKeyRequest) ProtoMessage() {}

func (x *PublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKeyRequest.ProtoReflect.Descriptor instead.
func (*PublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{2}
}

func (x *PublicKeyRequest) GetPublicKey() *PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *PublicKeyRequest) GetProofOfPossession() []byte {
	if x != nil {
		return x.ProofOfPossession
	}
	return nil
}

type PublicKey struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The cryptographic algorithm to use with the key material
	Algorithm PublicKeyAlgorithm `protobuf:"varint,1,opt,name=algorithm,proto3,enum=dev.sigstore.fulcio.v2.PublicKeyAlgorithm" json:"algorithm,omitempty"`
	// PKIX, ASN.1 DER or PEM-encoded public key. PEM is typically
	// of type PUBLIC KEY.
	Content       string `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PublicKey) Reset() {
	*x = PublicKey{}
	mi := &file_fulcio_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKey) ProtoMessage() {}

func (x *PublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKey.ProtoReflect.Descriptor instead.
func (*PublicKey) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{3}
}

func (x *PublicKey) GetAlgorithm() PublicKeyAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED
}

func (x *PublicKey) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

type SigningCertificate struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Certificate:
	//
	//	*SigningCertificate_SignedCertificateDetachedSct
	//	*SigningCertificate_SignedCertificateEmbeddedSct
	Certificate   isSigningCertificate_Certificate `protobuf_oneof:"certificate"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SigningCertificate) Reset() {
	*x = SigningCertificate{}
	mi := &file_fulcio_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SigningCertificate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificate) ProtoMessage() {}

func (x *SigningCertificate) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificate.ProtoReflect.Descriptor instead.
func (*SigningCertificate) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{4}
}

func (x *SigningCertificate) GetCertificate() isSigningCertificate_Certificate {
	if x != nil {
		return x.Certificate
	}
	return nil
}

func (x *SigningCertificate) GetSignedCertificateDetachedSct() *SigningCertificateDetachedSCT {
	if x != nil {
		if x, ok := x.Certificate.(*SigningCertificate_SignedCertificateDetachedSct); ok {
			return x.SignedCertificateDetachedSct
		}
	}
	return nil
}

func (x *SigningCertificate) GetSignedCertificateEmbeddedSct() *SigningCertificateEmbeddedSCT {
	if x != nil {
		if x, ok := x.Certificate.(*SigningCertificate_SignedCertificateEmbeddedSct); ok {
			return x.SignedCertificateEmbeddedSct
		}
	}
	return nil
}

type isSigningCertificate_Certificate interface {
	isSigningCertificate_Certificate()
}

type SigningCertificate_SignedCertificateDetachedSct struct {
	SignedCertificateDetachedSct *SigningCertificateDetachedSCT `protobuf:"bytes,1,opt,name=signed_certificate_detached_sct,json=signedCertificateDetachedSct,proto3,oneof"`
}

type SigningCertificate_SignedCertificateEmbeddedSct struct {
	SignedCertificateEmbeddedSct *SigningCertificateEmbeddedSCT `protobuf:"bytes,2,opt,name=signed_certificate_embedded_sct,json=signedCertificateEmbeddedSct,proto3,oneof"`
}

func (*SigningCertificate_SignedCertificateDetachedSct) isSigningCertificate_Certificate() {}

func (*SigningCertificate_SignedCertificateEmbeddedSct) isSigningCertificate_Certificate() {}

// (-- api-linter: core::0142::time-field-type=disabled
//
//	aip.dev/not-precedent: SCT is defined in RFC6962 and we keep the name consistent for easier understanding. --)
type SigningCertificateDetachedSCT struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The certificate chain serialized with the leaf certificate first, followed
	// by all intermediate certificates (if present), finishing with the root certificate.
	//
	// All values are PEM-encoded certificates.
	Chain *CertificateChain `protobuf:"bytes,1,opt,name=chain,proto3" json:"chain,omitempty"`
	// The Signed Certificate Timestamp (SCT) is a promise for including the certificate in
	// a certificate transparency log. It can be "stapled" to verify the inclusion of
	// a certificate in the log in an offline fashion.
	//
	// The SCT format is an AddChainResponse struct, defined in
	// https://github.com/google/certificate-transparency-go
	SignedCertificateTimestamp []byte `protobuf:"bytes,2,opt,name=signed_certificate_timestamp,json=signedCertificateTimestamp,proto3" json:"signed_certificate_timestamp,omitempty"`
	unknownFields              protoimpl.UnknownFields
	sizeCache                  protoimpl.SizeCache
}

func (x *SigningCertificateDetachedSCT) Reset() {
	*x = SigningCertificateDetachedSCT{}
	mi := &file_fulcio_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SigningCertificateDetachedSCT) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificateDetachedSCT) ProtoMessage() {}

func (x *SigningCertificateDetachedSCT) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificateDetachedSCT.ProtoReflect.Descriptor instead.
func (*SigningCertificateDetachedSCT) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{5}
}

func (x *SigningCertificateDetachedSCT) GetChain() *CertificateChain {
	if x != nil {
		return x.Chain
	}
	return nil
}

func (x *SigningCertificateDetachedSCT) GetSignedCertificateTimestamp() []byte {
	if x != nil {
		return x.SignedCertificateTimestamp
	}
	return nil
}

type SigningCertificateEmbeddedSCT struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The certificate chain serialized with the leaf certificate first, followed
	// by all intermediate certificates (if present), finishing with the root certificate.
	//
	// All values are PEM-encoded certificates.
	//
	// The leaf certificate contains an embedded Signed Certificate Timestamp (SCT) to
	// verify inclusion of the certificate in a log. The SCT format is a SignedCertificateTimestampList,
	// as defined in https://datatracker.ietf.org/doc/html/rfc6962#section-3.3
	Chain         *CertificateChain `protobuf:"bytes,1,opt,name=chain,proto3" json:"chain,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SigningCertificateEmbeddedSCT) Reset() {
	*x = SigningCertificateEmbeddedSCT{}
	mi := &file_fulcio_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SigningCertificateEmbeddedSCT) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificateEmbeddedSCT) ProtoMessage() {}

func (x *SigningCertificateEmbeddedSCT) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificateEmbeddedSCT.ProtoReflect.Descriptor instead.
func (*SigningCertificateEmbeddedSCT) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{6}
}

func (x *SigningCertificateEmbeddedSCT) GetChain() *CertificateChain {
	if x != nil {
		return x.Chain
	}
	return nil
}

// This is created for forward compatibility in case we want to add fields to the TrustBundle service in the future
type GetTrustBundleRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetTrustBundleRequest) Reset() {
	*x = GetTrustBundleRequest{}
	mi := &file_fulcio_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetTrustBundleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetTrustBundleRequest) ProtoMessage() {}

func (x *GetTrustBundleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetTrustBundleRequest.ProtoReflect.Descriptor instead.
func (*GetTrustBundleRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{7}
}

type TrustBundle struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The set of PEM-encoded certificate chains for this Fulcio instance; each chain will start with any
	// intermediate certificates (if present), finishing with the root certificate.
	Chains        []*CertificateChain `protobuf:"bytes,1,rep,name=chains,proto3" json:"chains,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TrustBundle) Reset() {
	*x = TrustBundle{}
	mi := &file_fulcio_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TrustBundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TrustBundle) ProtoMessage() {}

func (x *TrustBundle) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TrustBundle.ProtoReflect.Descriptor instead.
func (*TrustBundle) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{8}
}

func (x *TrustBundle) GetChains() []*CertificateChain {
	if x != nil {
		return x.Chains
	}
	return nil
}

type CertificateChain struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The PEM-encoded certificate chain, ordered from leaf to intermediate to root as applicable.
	Certificates  []string `protobuf:"bytes,1,rep,name=certificates,proto3" json:"certificates,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CertificateChain) Reset() {
	*x = CertificateChain{}
	mi := &file_fulcio_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CertificateChain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateChain) ProtoMessage() {}

func (x *CertificateChain) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateChain.ProtoReflect.Descriptor instead.
func (*CertificateChain) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{9}
}

func (x *CertificateChain) GetCertificates() []string {
	if x != nil {
		return x.Certificates
	}
	return nil
}

// This is created for forward compatibility in case we want to add fields in the future.
type GetConfigurationRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetConfigurationRequest) Reset() {
	*x = GetConfigurationRequest{}
	mi := &file_fulcio_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetConfigurationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConfigurationRequest) ProtoMessage() {}

func (x *GetConfigurationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConfigurationRequest.ProtoReflect.Descriptor instead.
func (*GetConfigurationRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{10}
}

// The configuration for the Fulcio instance.
type Configuration struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The OIDC issuers supported by this Fulcio instance.
	Issuers       []*OIDCIssuer `protobuf:"bytes,1,rep,name=issuers,proto3" json:"issuers,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Configuration) Reset() {
	*x = Configuration{}
	mi := &file_fulcio_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Configuration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Configuration) ProtoMessage() {}

func (x *Configuration) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Configuration.ProtoReflect.Descriptor instead.
func (*Configuration) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{11}
}

func (x *Configuration) GetIssuers() []*OIDCIssuer {
	if x != nil {
		return x.Issuers
	}
	return nil
}

// Metadata about an OIDC issuer.
type OIDCIssuer struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Issuer:
	//
	//	*OIDCIssuer_IssuerUrl
	//	*OIDCIssuer_WildcardIssuerUrl
	Issuer isOIDCIssuer_Issuer `protobuf_oneof:"issuer"`
	// The expected audience of the OIDC token for the issuer.
	Audience string `protobuf:"bytes,3,opt,name=audience,proto3" json:"audience,omitempty"`
	// The OIDC claim that must be signed for a proof of possession challenge.
	ChallengeClaim string `protobuf:"bytes,4,opt,name=challenge_claim,json=challengeClaim,proto3" json:"challenge_claim,omitempty"`
	// The expected SPIFFE trust domain. Only present when the OIDC issuer issues tokens for SPIFFE identities.
	SpiffeTrustDomain string `protobuf:"bytes,5,opt,name=spiffe_trust_domain,json=spiffeTrustDomain,proto3" json:"spiffe_trust_domain,omitempty"`
	// The type of the IDP (e.g. "email", "username", etc.).
	IssuerType string `protobuf:"bytes,6,opt,name=issuer_type,json=issuerType,proto3" json:"issuer_type,omitempty"`
	// The expected subject domain. Only present when the OIDC issuer issues tokens for URI or username identities.
	SubjectDomain string `protobuf:"bytes,7,opt,name=subject_domain,json=subjectDomain,proto3" json:"subject_domain,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *OIDCIssuer) Reset() {
	*x = OIDCIssuer{}
	mi := &file_fulcio_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *OIDCIssuer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OIDCIssuer) ProtoMessage() {}

func (x *OIDCIssuer) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OIDCIssuer.ProtoReflect.Descriptor instead.
func (*OIDCIssuer) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{12}
}

func (x *OIDCIssuer) GetIssuer() isOIDCIssuer_Issuer {
	if x != nil {
		return x.Issuer
	}
	return nil
}

func (x *OIDCIssuer) GetIssuerUrl() string {
	if x != nil {
		if x, ok := x.Issuer.(*OIDCIssuer_IssuerUrl); ok {
			return x.IssuerUrl
		}
	}
	return ""
}

func (x *OIDCIssuer) GetWildcardIssuerUrl() string {
	if x != nil {
		if x, ok := x.Issuer.(*OIDCIssuer_WildcardIssuerUrl); ok {
			return x.WildcardIssuerUrl
		}
	}
	return ""
}

func (x *OIDCIssuer) GetAudience() string {
	if x != nil {
		return x.Audience
	}
	return ""
}

func (x *OIDCIssuer) GetChallengeClaim() string {
	if x != nil {
		return x.ChallengeClaim
	}
	return ""
}

func (x *OIDCIssuer) GetSpiffeTrustDomain() string {
	if x != nil {
		return x.SpiffeTrustDomain
	}
	return ""
}

func (x *OIDCIssuer) GetIssuerType() string {
	if x != nil {
		return x.IssuerType
	}
	return ""
}

func (x *OIDCIssuer) GetSubjectDomain() string {
	if x != nil {
		return x.SubjectDomain
	}
	return ""
}

type isOIDCIssuer_Issuer interface {
	isOIDCIssuer_Issuer()
}

type OIDCIssuer_IssuerUrl struct {
	// The URL of the OIDC issuer.
	IssuerUrl string `protobuf:"bytes,1,opt,name=issuer_url,json=issuerUrl,proto3,oneof"`
}

type OIDCIssuer_WildcardIssuerUrl struct {
	// The URL of wildcard OIDC issuer, e.g. "https://oidc.eks.*.amazonaws.com/id/*".
	// When comparing the issuer, the wildcards will be replaced by "[-_a-zA-Z0-9]+".
	WildcardIssuerUrl string `protobuf:"bytes,2,opt,name=wildcard_issuer_url,json=wildcardIssuerUrl,proto3,oneof"`
}

func (*OIDCIssuer_IssuerUrl) isOIDCIssuer_Issuer() {}

func (*OIDCIssuer_WildcardIssuerUrl) isOIDCIssuer_Issuer() {}

var File_fulcio_proto protoreflect.FileDescriptor

const file_fulcio_proto_rawDesc = "" +
	"\n" +
	"\ffulcio.proto\x12\x16dev.sigstore.fulcio.v2\x1a\x1cgoogle/api/annotations.proto\x1a\x1fgoogle/api/field_behavior.proto\x1a.protoc-gen-openapiv2/options/annotations.proto\"\x9d\x02\n" +
	"\x1fCreateSigningCertificateRequest\x12K\n" +
	"\vcredentials\x18\x01 \x01(\v2#.dev.sigstore.fulcio.v2.CredentialsB\x04\xe2A\x01\x02R\vcredentials\x12^\n" +
	"\x12public_key_request\x18\x02 \x01(\v2(.dev.sigstore.fulcio.v2.PublicKeyRequestB\x04\xe2A\x01\x02H\x00R\x10publicKeyRequest\x12F\n" +
	"\x1bcertificate_signing_request\x18\x03 \x01(\fB\x04\xe2A\x01\x02H\x00R\x19certificateSigningRequestB\x05\n" +
	"\x03key\"N\n" +
	"\vCredentials\x120\n" +
	"\x13oidc_identity_token\x18\x01 \x01(\tH\x00R\x11oidcIdentityTokenB\r\n" +
	"\vcredentials\"\x90\x01\n" +
	"\x10PublicKeyRequest\x12F\n" +
	"\n" +
	"public_key\x18\x01 \x01(\v2!.dev.sigstore.fulcio.v2.PublicKeyB\x04\xe2A\x01\x02R\tpublicKey\x124\n" +
	"\x13proof_of_possession\x18\x02 \x01(\fB\x04\xe2A\x01\x02R\x11proofOfPossession\"u\n" +
	"\tPublicKey\x12H\n" +
	"\talgorithm\x18\x01 \x01(\x0e2*.dev.sigstore.fulcio.v2.PublicKeyAlgorithmR\talgorithm\x12\x1e\n" +
	"\acontent\x18\x02 \x01(\tB\x04\xe2A\x01\x02R\acontent\"\xa3\x02\n" +
	"\x12SigningCertificate\x12~\n" +
	"\x1fsigned_certificate_detached_sct\x18\x01 \x01(\v25.dev.sigstore.fulcio.v2.SigningCertificateDetachedSCTH\x00R\x1csignedCertificateDetachedSct\x12~\n" +
	"\x1fsigned_certificate_embedded_sct\x18\x02 \x01(\v25.dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCTH\x00R\x1csignedCertificateEmbeddedSctB\r\n" +
	"\vcertificate\"\xa1\x01\n" +
	"\x1dSigningCertificateDetachedSCT\x12>\n" +
	"\x05chain\x18\x01 \x01(\v2(.dev.sigstore.fulcio.v2.CertificateChainR\x05chain\x12@\n" +
	"\x1csigned_certificate_timestamp\x18\x02 \x01(\fR\x1asignedCertificateTimestamp\"_\n" +
	"\x1dSigningCertificateEmbeddedSCT\x12>\n" +
	"\x05chain\x18\x01 \x01(\v2(.dev.sigstore.fulcio.v2.CertificateChainR\x05chain\"\x17\n" +
	"\x15GetTrustBundleRequest\"O\n" +
	"\vTrustBundle\x12@\n" +
	"\x06chains\x18\x01 \x03(\v2(.dev.sigstore.fulcio.v2.CertificateChainR\x06chains\"6\n" +
	"\x10CertificateChain\x12\"\n" +
	"\fcertificates\x18\x01 \x03(\tR\fcertificates\"\x19\n" +
	"\x17GetConfigurationRequest\"M\n" +
	"\rConfiguration\x12<\n" +
	"\aissuers\x18\x01 \x03(\v2\".dev.sigstore.fulcio.v2.OIDCIssuerR\aissuers\"\xa6\x02\n" +
	"\n" +
	"OIDCIssuer\x12\x1f\n" +
	"\n" +
	"issuer_url\x18\x01 \x01(\tH\x00R\tissuerUrl\x120\n" +
	"\x13wildcard_issuer_url\x18\x02 \x01(\tH\x00R\x11wildcardIssuerUrl\x12\x1a\n" +
	"\baudience\x18\x03 \x01(\tR\baudience\x12'\n" +
	"\x0fchallenge_claim\x18\x04 \x01(\tR\x0echallengeClaim\x12.\n" +
	"\x13spiffe_trust_domain\x18\x05 \x01(\tR\x11spiffeTrustDomain\x12\x1f\n" +
	"\vissuer_type\x18\x06 \x01(\tR\n" +
	"issuerType\x12%\n" +
	"\x0esubject_domain\x18\a \x01(\tR\rsubjectDomainB\b\n" +
	"\x06issuer*_\n" +
	"\x12PublicKeyAlgorithm\x12$\n" +
	" PUBLIC_KEY_ALGORITHM_UNSPECIFIED\x10\x00\x12\v\n" +
	"\aRSA_PSS\x10\x01\x12\t\n" +
	"\x05ECDSA\x10\x02\x12\v\n" +
	"\aED25519\x10\x032\xb6\x03\n" +
	"\x02CA\x12\x9f\x01\n" +
	"\x18CreateSigningCertificate\x127.dev.sigstore.fulcio.v2.CreateSigningCertificateRequest\x1a*.dev.sigstore.fulcio.v2.SigningCertificate\"\x1e\x82\xd3\xe4\x93\x02\x18:\x01*\"\x13/api/v2/signingCert\x12\x81\x01\n" +
	"\x0eGetTrustBundle\x12-.dev.sigstore.fulcio.v2.GetTrustBundleRequest\x1a#.dev.sigstore.fulcio.v2.TrustBundle\"\x1b\x82\xd3\xe4\x93\x02\x15\x12\x13/api/v2/trustBundle\x12\x89\x01\n" +
	"\x10GetConfiguration\x12/.dev.sigstore.fulcio.v2.GetConfigurationRequest\x1a%.dev.sigstore.fulcio.v2.Configuration\"\x1d\x82\xd3\xe4\x93\x02\x17\x12\x15/api/v2/configurationB\x8f\x03\x92A\xb1\x02\x12\xb9\x01\n" +
	"\x06Fulcio\"\\\n" +
	"\x17sigstore Fulcio project\x12\"https://github.com/sigstore/fulcio\x1a\x1dsigstore-dev@googlegroups.com*J\n" +
	"\x12Apache License 2.0\x124https://github.com/sigstore/fulcio/blob/main/LICENSE2\x052.0.0\x1a\x13fulcio.sigstore.dev*\x01\x012\x10application/json:\x10application/jsonr7\n" +
	"\x11More about Fulcio\x12\"https://github.com/sigstore/fulcio\n" +
	"\x16dev.sigstore.fulcio.v2B\vFulcioProtoP\x01Z1github.com/sigstore/fulcio/pkg/generated/protobufb\x06proto3"

var (
	file_fulcio_proto_rawDescOnce sync.Once
	file_fulcio_proto_rawDescData []byte
)

func file_fulcio_proto_rawDescGZIP() []byte {
	file_fulcio_proto_rawDescOnce.Do(func() {
		file_fulcio_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_fulcio_proto_rawDesc), len(file_fulcio_proto_rawDesc)))
	})
	return file_fulcio_proto_rawDescData
}

var file_fulcio_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_fulcio_proto_msgTypes = make([]protoimpl.MessageInfo, 13)
var file_fulcio_proto_goTypes = []any{
	(PublicKeyAlgorithm)(0),                 // 0: dev.sigstore.fulcio.v2.PublicKeyAlgorithm
	(*CreateSigningCertificateRequest)(nil), // 1: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest
	(*Credentials)(nil),                     // 2: dev.sigstore.fulcio.v2.Credentials
	(*PublicKeyRequest)(nil),                // 3: dev.sigstore.fulcio.v2.PublicKeyRequest
	(*PublicKey)(nil),                       // 4: dev.sigstore.fulcio.v2.PublicKey
	(*SigningCertificate)(nil),              // 5: dev.sigstore.fulcio.v2.SigningCertificate
	(*SigningCertificateDetachedSCT)(nil),   // 6: dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT
	(*SigningCertificateEmbeddedSCT)(nil),   // 7: dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT
	(*GetTrustBundleRequest)(nil),           // 8: dev.sigstore.fulcio.v2.GetTrustBundleRequest
	(*TrustBundle)(nil),                     // 9: dev.sigstore.fulcio.v2.TrustBundle
	(*CertificateChain)(nil),                // 10: dev.sigstore.fulcio.v2.CertificateChain
	(*GetConfigurationRequest)(nil),         // 11: dev.sigstore.fulcio.v2.GetConfigurationRequest
	(*Configuration)(nil),                   // 12: dev.sigstore.fulcio.v2.Configuration
	(*OIDCIssuer)(nil),                      // 13: dev.sigstore.fulcio.v2.OIDCIssuer
}
var file_fulcio_proto_depIdxs = []int32{
	2,  // 0: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest.credentials:type_name -> dev.sigstore.fulcio.v2.Credentials
	3,  // 1: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest.public_key_request:type_name -> dev.sigstore.fulcio.v2.PublicKeyRequest
	4,  // 2: dev.sigstore.fulcio.v2.PublicKeyRequest.public_key:type_name -> dev.sigstore.fulcio.v2.PublicKey
	0,  // 3: dev.sigstore.fulcio.v2.PublicKey.algorithm:type_name -> dev.sigstore.fulcio.v2.PublicKeyAlgorithm
	6,  // 4: dev.sigstore.fulcio.v2.SigningCertificate.signed_certificate_detached_sct:type_name -> dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT
	7,  // 5: dev.sigstore.fulcio.v2.SigningCertificate.signed_certificate_embedded_sct:type_name -> dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT
	10, // 6: dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT.chain:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	10, // 7: dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT.chain:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	10, // 8: dev.sigstore.fulcio.v2.TrustBundle.chains:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	13, // 9: dev.sigstore.fulcio.v2.Configuration.issuers:type_name -> dev.sigstore.fulcio.v2.OIDCIssuer
	1,  // 10: dev.sigstore.fulcio.v2.CA.CreateSigningCertificate:input_type -> dev.sigstore.fulcio.v2.CreateSigningCertificateRequest
	8,  // 11: dev.sigstore.fulcio.v2.CA.GetTrustBundle:input_type -> dev.sigstore.fulcio.v2.GetTrustBundleRequest
	11, // 12: dev.sigstore.fulcio.v2.CA.GetConfiguration:input_type -> dev.sigstore.fulcio.v2.GetConfigurationRequest
	5,  // 13: dev.sigstore.fulcio.v2.CA.CreateSigningCertificate:output_type -> dev.sigstore.fulcio.v2.SigningCertificate
	9,  // 14: dev.sigstore.fulcio.v2.CA.GetTrustBundle:output_type -> dev.sigstore.fulcio.v2.TrustBundle
	12, // 15: dev.sigstore.fulcio.v2.CA.GetConfiguration:output_type -> dev.sigstore.fulcio.v2.Configuration
	13, // [13:16] is the sub-list for method output_type
	10, // [10:13] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_fulcio_proto_init() }
func file_fulcio_proto_init() {
	if File_fulcio_proto != nil {
		return
	}
	file_fulcio_proto_msgTypes[0].OneofWrappers = []any{
		(*CreateSigningCertificateRequest_PublicKeyRequest)(nil),
		(*CreateSigningCertificateRequest_CertificateSigningRequest)(nil),
	}
	file_fulcio_proto_msgTypes[1].OneofWrappers = []any{
		(*Credentials_OidcIdentityToken)(nil),
	}
	file_fulcio_proto_msgTypes[4].OneofWrappers = []any{
		(*SigningCertificate_SignedCertificateDetachedSct)(nil),
		(*SigningCertificate_SignedCertificateEmbeddedSct)(nil),
	}
	file_fulcio_proto_msgTypes[12].OneofWrappers = []any{
		(*OIDCIssuer_IssuerUrl)(nil),
		(*OIDCIssuer_WildcardIssuerUrl)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_fulcio_proto_rawDesc), len(file_fulcio_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   13,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_fulcio_proto_goTypes,
		DependencyIndexes: file_fulcio_proto_depIdxs,
		EnumInfos:         file_fulcio_proto_enumTypes,
		MessageInfos:      file_fulcio_proto_msgTypes,
	}.Build()
	File_fulcio_proto = out.File
	file_fulcio_proto_goTypes = nil
	file_fulcio_proto_depIdxs = nil
}
