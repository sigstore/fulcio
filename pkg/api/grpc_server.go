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
	"crypto/x509"
	"encoding/json"

	empty "github.com/golang/protobuf/ptypes/empty"
	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ctl"
	fulciogrpc "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type grpcCAServer struct {
	fulciogrpc.UnimplementedCAServer
	ct ctl.Client
	ca certauth.CertificateAuthority
}

func NewGRPCCAServer(ct ctl.Client, ca certauth.CertificateAuthority) fulciogrpc.CAServer {
	return &grpcCAServer{
		ct: ct,
		ca: ca,
	}
}

const (
	MetadataOIDCTokenKey = "oidcidentitytoken"
)

func (g *grpcCAServer) CreateSigningCertificate(ctx context.Context, request *fulciogrpc.CreateSigningCertificateRequest) (*fulciogrpc.SigningCertificate, error) {
	logger := log.ContextLogger(ctx)

	// OIDC token either is passed in gRPC field or was extracted from HTTP headers
	token := ""
	if request.Credentials != nil {
		token = request.Credentials.GetOidcIdentityToken()
	}
	if token == "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			vals := md.Get(MetadataOIDCTokenKey)
			if len(vals) == 1 {
				token = vals[0]
			}
		}
	}

	principal, err := authorize(ctx, token)
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.Unauthenticated, err, invalidCredentials)
	}

	publicKeyBytes := request.PublicKey.Content
	// try to unmarshal as DER
	publicKey, err := x509.ParsePKIXPublicKey([]byte(publicKeyBytes))
	if err != nil {
		// try to unmarshal as PEM
		logger.Debugf("error parsing public key as DER, trying pem: %v", err.Error())
		publicKey, err = cryptoutils.UnmarshalPEMToPublicKey([]byte(publicKeyBytes))
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, invalidPublicKey)
		}
	}

	subject, err := ExtractSubject(ctx, principal, publicKey, request.ProofOfPossession)
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, invalidSignature)
	}

	var csc *certauth.CodeSigningCertificate
	var sctBytes []byte
	// TODO: prefer embedding SCT if possible
	if _, ok := g.ca.(certauth.EmbeddedSCTCA); !ok {
		// currently configured CA doesn't support pre-certificate flow required to embed SCT in final certificate
		csc, err = g.ca.CreateCertificate(ctx, subject)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, err.Error())
			}
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, genericCAError)
		}

		// Submit to CTL
		if g.ct != nil {
			sct, err := g.ct.AddChain(ctx, csc)
			if err != nil {
				return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToEnterCertInCTL)
			}
			sctBytes, err = json.Marshal(sct)
			if err != nil {
				return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalSCT)
			}
		} else {
			logger.Info("Skipping CT log upload.")
		}
	}

	metricNewEntries.Inc()

	finalPEM, err := csc.CertPEM()
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
	}

	finalChainPEM, err := csc.ChainPEM()
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
	}

	result := &fulciogrpc.SigningCertificate{
		Chain: &fulciogrpc.CertificateChain{
			Certificates: []string{string(finalPEM), string(finalChainPEM)},
		},
	}

	if len(sctBytes) > 0 {
		result.SignedCertificateTimestamp = sctBytes
	}

	return result, nil
}

func (g *grpcCAServer) GetTrustBundle(ctx context.Context, _ *empty.Empty) (*fulciogrpc.TrustBundle, error) {
	logger := log.ContextLogger(ctx)

	root, err := g.ca.Root(ctx)
	if err != nil {
		logger.Error("Error retrieving root cert: ", err)
		return nil, handleFulcioGRPCError(ctx, codes.Internal, err, genericCAError)
	}

	return &fulciogrpc.TrustBundle{
		Chains: []*fulciogrpc.CertificateChain{{
			Certificates: []string{string(root)},
		}},
	}, nil
}
