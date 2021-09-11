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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sigstore/fulcio/pkg/challenges"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/viper"
)

func SigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	// none of the following cases should happen if the authentication path is working correctly; checking to be defensive
	if principal == nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, errors.New("no principal supplied to request"), invalidCredentials)
	}

	publicKey := *params.CertificateRequest.PublicKey.Content
	subj, err := Subject(ctx, principal, config.Config(), publicKey, *params.CertificateRequest.SignedEmailAddress)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Bytes: publicKey,
		Type:  "PUBLIC KEY",
	})

	var PemCertificate string
	var PemCertificateChain []string

	switch viper.GetString("ca") {
	case "googleca":
		PemCertificate, PemCertificateChain, err = GoogleCASigningCertHandler(ctx, subj, publicKeyPEM)
	case "fulcioca":
		PemCertificate, PemCertificateChain, err = FulcioCASigningCertHandler(subj, publicKey)
	default:
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, genericCAError)
	}
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, genericCAError)
	}

	// Submit to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", subj.Value)
	var sctBytes []byte
	ctURL := viper.GetString("ct-log-url")
	if ctURL != "" {
		c := ctl.New(ctURL)
		sct, err := c.AddChain(PemCertificate, PemCertificateChain)
		if err != nil {
			return handleFulcioAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(failedToEnterCertInCTL, ctURL))
		}
		sctBytes, err = json.Marshal(sct)
		if err != nil {
			return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToMarshalSCT)
		}
		log.Logger.Info("CTL Submission Signature Received: ", sct.Signature)
		log.Logger.Info("CTL Submission ID Received: ", sct.ID)
	} else {
		log.Logger.Info("Skipping CT log upload.")
	}

	metricNewEntries.Inc()

	var ret strings.Builder
	fmt.Fprintf(&ret, "%s\n", PemCertificate)
	for _, cert := range PemCertificateChain {
		fmt.Fprintf(&ret, "%s\n", cert)
	}

	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String())).WithSCT(sctBytes)
}

func Subject(ctx context.Context, tok *oidc.IDToken, cfg config.FulcioConfig, publicKey, challenge []byte) (*challenges.ChallengeResult, error) {
	iss := cfg.OIDCIssuers[tok.Issuer]
	switch iss.Type {
	case config.IssuerTypeEmail:
		return challenges.Email(ctx, tok, publicKey, challenge)
	case config.IssuerTypeSpiffe:
		return challenges.Spiffe(ctx, tok, publicKey, challenge)
	case config.IssuerTypeGithubWorkflow:
		return challenges.GithubWorkflow(ctx, tok, publicKey, challenge)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)
	}
}
