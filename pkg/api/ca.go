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

package api

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func SigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	logger := log.ContextLogger(ctx)

	// none of the following cases should happen if the authentication path is working correctly; checking to be defensive
	if principal == nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, errors.New("no principal supplied to request"), invalidCredentials)
	}

	publicKeyBytes := *params.CertificateRequest.PublicKey.Content
	// try to unmarshal as DER
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		// try to unmarshal as PEM
		logger.Debugf("error parsing public key as DER, trying pem: %v", err.Error())
		publicKey, err = cryptoutils.UnmarshalPEMToPublicKey(publicKeyBytes)
		if err != nil {
			return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidPublicKey)
		}
	}

	subject, err := ExtractSubject(ctx, principal, publicKey, *params.CertificateRequest.SignedEmailAddress)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	ca := GetCA(ctx)

	var csc *certauth.CodeSigningCertificate
	var sctBytes []byte
	// TODO: prefer embedding SCT if possible
	if _, ok := ca.(certauth.EmbeddedSCTCA); !ok {
		// currently configured CA doesn't support pre-certificate flow required to embed SCT in final certificate
		csc, err = ca.CreateCertificate(ctx, subject)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				return handleFulcioAPIError(params, http.StatusBadRequest, err, err.Error())
			}
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			return handleFulcioAPIError(params, http.StatusInternalServerError, err, genericCAError)
		}

		// TODO: initialize CTL client once
		// Submit to CTL
		logger.Info("Submitting CTL inclusion for OIDC grant: ", subject.Value)
		ctURL := GetCTLogURL(ctx)
		if ctURL != "" {
			c := ctl.New(ctURL)
			sct, err := c.AddChain(csc)
			if err != nil {
				return handleFulcioAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(failedToEnterCertInCTL, ctURL))
			}
			sctBytes, err = json.Marshal(sct)
			if err != nil {
				return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToMarshalSCT)
			}
			logger.Info("CTL Submission Signature Received: ", sct.Signature)
			logger.Info("CTL Submission ID Received: ", sct.ID)
		} else {
			logger.Info("Skipping CT log upload.")
		}
	}

	metricNewEntries.Inc()

	var ret strings.Builder
	finalPEM, err := csc.CertPEM()
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToMarshalCert)
	}
	fmt.Fprintf(&ret, "%s\n", finalPEM)
	finalChainPEM, err := csc.ChainPEM()
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToMarshalCert)
	}
	if len(finalChainPEM) > 0 {
		fmt.Fprintf(&ret, "%s\n", finalChainPEM)
	}

	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String())).WithSCT(sctBytes)
}

func ExtractSubject(ctx context.Context, tok *oidc.IDToken, publicKey crypto.PublicKey, challenge []byte) (*challenges.ChallengeResult, error) {
	iss, ok := config.FromContext(ctx).GetIssuer(tok.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", tok.Issuer)
	}
	switch iss.Type {
	case config.IssuerTypeEmail:
		return challenges.Email(ctx, tok, publicKey, challenge)
	case config.IssuerTypeSpiffe:
		return challenges.Spiffe(ctx, tok, publicKey, challenge)
	case config.IssuerTypeGithubWorkflow:
		return challenges.GithubWorkflow(ctx, tok, publicKey, challenge)
	case config.IssuerTypeKubernetes:
		return challenges.Kubernetes(ctx, tok, publicKey, challenge)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)
	}
}

type caKey struct{}

// WithCA associates the provided certificate authority with the provided context.
func WithCA(ctx context.Context, ca certauth.CertificateAuthority) context.Context {
	return context.WithValue(ctx, caKey{}, ca)
}

// GetCA accesses the certificate authority associated with the provided context.
func GetCA(ctx context.Context) certauth.CertificateAuthority {
	untyped := ctx.Value(caKey{})
	if untyped == nil {
		return nil
	}
	return untyped.(certauth.CertificateAuthority)
}

type ctKey struct{}

// WithCTLogURL associates the provided certificate transparency log URL with
// the provided context.
func WithCTLogURL(ctx context.Context, ct string) context.Context {
	return context.WithValue(ctx, ctKey{}, ct)
}

// GetCTLogURL accesses the certificate transparency log URL associated with
// the provided context.
func GetCTLogURL(ctx context.Context) string {
	untyped := ctx.Value(ctKey{})
	if untyped == nil {
		return ""
	}
	return untyped.(string)
}
