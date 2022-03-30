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
//

package api

import (
	"context"
	"encoding/base64"
	"strings"

	empty "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	fulciogrpc "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/generated/protobuf/legacy"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	PEMCertificateChain         = "application/pem-certificate-chain"
	SCTMetadataKey              = "x-sct"
	HTTPResponseCodeMetadataKey = "x-http-code"
)

type legacyGRPCCAServer struct {
	legacy.UnimplementedCAServer
	v2Server fulciogrpc.CAServer
}

func NewLegacyGRPCCAServer(v2Server fulciogrpc.CAServer) legacy.CAServer {
	return &legacyGRPCCAServer{
		v2Server: v2Server,
	}
}

func (l *legacyGRPCCAServer) CreateSigningCertificate(ctx context.Context, request *legacy.CreateSigningCertificateRequest) (*httpbody.HttpBody, error) {
	// OIDC token either is passed in gRPC field or was extracted from HTTP headers
	token := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get(MetadataOIDCTokenKey)
		if len(vals) == 1 {
			token = vals[0]
		}
	}

	creds := fulciogrpc.Credentials{
		Credentials: &fulciogrpc.Credentials_OidcIdentityToken{
			OidcIdentityToken: token,
		},
	}

	// create new CA request mapping fields from legacy to actual
	algorithmEnum, ok := fulciogrpc.PublicKeyAlgorithm_value[strings.ToUpper(request.PublicKey.Algorithm)] //lint:ignore SA1019 this is valid because we're converting from v1beta to v1 API
	if !ok {
		algorithmEnum = int32(fulciogrpc.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED)
	}

	v2Request := fulciogrpc.CreateSigningCertificateRequest{
		Credentials: &creds,
		PublicKey: &fulciogrpc.PublicKey{
			Algorithm: fulciogrpc.PublicKeyAlgorithm(algorithmEnum),
			Content:   string(request.PublicKey.Content), //lint:ignore SA1019 this is valid because we're converting from v1beta to v1 API
		},
		ProofOfPossession: request.SignedEmailAddress, //lint:ignore SA1019 this is valid because we're converting from v1beta to v1 API
	}

	v2Response, err := l.v2Server.CreateSigningCertificate(ctx, &v2Request)
	if err != nil {
		return nil, errors.Wrap(err, "legacy handler")
	}

	// we need to return a HTTP 201 Created response code to be backward compliant
	if err = grpc.SetHeader(ctx, metadata.Pairs(HTTPResponseCodeMetadataKey, "201")); err != nil {
		return nil, errors.Wrap(err, "legacy handler")
	}

	// the SCT for the certificate needs to be returned in a HTTP response header
	sctString := base64.StdEncoding.EncodeToString(v2Response.SignedCertificateTimestamp)
	if sctString != "" {
		if err := grpc.SetHeader(ctx, metadata.Pairs(SCTMetadataKey, sctString)); err != nil {
			return nil, errors.Wrap(err, "legacy handler")
		}
	}

	var concatCerts strings.Builder
	for _, cert := range v2Response.Chain.Certificates {
		concatCerts.WriteString(cert)
	}

	return &httpbody.HttpBody{
		ContentType: PEMCertificateChain,
		Data:        []byte(string(strings.TrimSpace(concatCerts.String()))),
	}, nil
}

func (l *legacyGRPCCAServer) GetRootCertificate(ctx context.Context, _ *empty.Empty) (*httpbody.HttpBody, error) {
	v2Response, err := l.v2Server.GetTrustBundle(ctx, nil)
	if err != nil {
		return nil, errors.Wrap(err, "legacy handler")
	}

	var concatCerts strings.Builder
	for _, cert := range v2Response.Chain.Certificates {
		concatCerts.WriteString(cert)
		concatCerts.WriteRune('\n')
	}

	return &httpbody.HttpBody{
		ContentType: PEMCertificateChain,
		Data:        []byte(strings.TrimSpace(concatCerts.String())),
	}, nil
}
