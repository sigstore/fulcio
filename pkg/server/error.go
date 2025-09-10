// Copyright 2021 The Sigstore Authors.
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

package server

import (
	"context"

	"github.com/sigstore/fulcio/pkg/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	invalidSignature       = "The signature supplied in the request could not be verified"
	invalidPublicKey       = "The public key supplied in the request could not be parsed"
	invalidCSR             = "The certificate signing request could not be parsed"
	failedToEnterCertInCTL = "Error entering certificate in CTL"
	failedToMarshalSCT     = "Error marshaling signed certificate timestamp"
	failedToMarshalCert    = "Error marshaling code signing certificate"
	insecurePublicKey      = "The public key supplied in the request is insecure"
	// nolint:gosec // false positive G101
	invalidCredentials = "There was an error processing the credentials for this request" //lint:ignore U1000 Used in past
	// nolint:gosec // false positive G101
	invalidIdentityToken                    = "There was an error processing the identity token"
	genericCAError                          = "error communicating with CA backend"
	retrieveTrustBundleCAError              = "error retrieving trust bundle from CA backend"
	marshalingCertificateChainBundleCAError = "error marshaling the certificate chain of the bundle"
	loadingFulcioConfigurationError         = "error loading fulcio configuration"
)

func handleFulcioGRPCError(ctx context.Context, code codes.Code, err error, message string, fields ...interface{}) error {
	// Use log level "warning" for codes that are likely client errors, see https://grpc.github.io/grpc/core/md_doc_statuscodes.html
	switch code {
	case codes.InvalidArgument,
		codes.NotFound,
		codes.AlreadyExists,
		codes.PermissionDenied,
		codes.Unauthenticated,
		codes.FailedPrecondition,
		codes.OutOfRange,
		codes.Aborted,
		codes.ResourceExhausted,
		codes.Canceled:
		log.ContextLogger(ctx).Warnw(err.Error(), append([]interface{}{"code", code, "clientMessage", message, "error", err}, fields...)...)
	default:
		log.ContextLogger(ctx).Errorw(err.Error(), append([]interface{}{"code", code, "clientMessage", message, "error", err}, fields...)...)
	}
	return status.Error(code, message)
}
