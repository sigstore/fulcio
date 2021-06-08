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
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sigstore/fulcio/pkg/ca/googleca"
	"net/http"
	"strings"

	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

func GoogleSigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	// none of the following cases should happen if the authentication path is working correctly; checking to be defensive
	if principal == nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, errors.New("no principal supplied to request"), invalidCredentials)
	}

	publicKey := *params.CertificateRequest.PublicKey.Content
	subj, err := subject(ctx, principal, config.Config(), publicKey, *params.CertificateRequest.SignedEmailAddress)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Bytes: publicKey,
		Type:  "PUBLIC KEY",
	})
	// Now issue cert!

	parent := viper.GetString("gcp_private_ca_parent")

	req := googleca.Req(parent, subj, publicKeyPEM)
	log.Logger.Infof("requesting cert from %s for %v", parent, subject)

	resp, err := googleca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}

	// Submit to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", subject)
	ctURL := viper.GetString("ct-log-url")
	if ctURL != "" {
		c := ctl.New(ctURL)
		ct, err := c.AddChain(resp.PemCertificate, resp.PemCertificateChain)
		if err != nil {
			return handleFulcioAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(failedToEnterCertInCTL, ctURL))
		}
		log.Logger.Info("CTL Submission Signature Received: ", ct.Signature)
		log.Logger.Info("CTL Submission ID Received: ", ct.ID)
	} else {
		log.Logger.Info("Skipping CT log upload.")
	}

	metricNewEntries.Inc()

	var ret strings.Builder
	fmt.Fprintf(&ret, "%s\n", resp.PemCertificate)
	for _, cert := range resp.PemCertificateChain {
		fmt.Fprintf(&ret, "%s\n", cert)
	}
	fmt.Println(resp.PemCertificate)
	//TODO: return SCT and SCT URL
	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String()))
}

func subject(ctx context.Context, tok *oidc.IDToken, cfg config.FulcioConfig, publicKey, challenge []byte) (*privatecapb.CertificateConfig_SubjectConfig, error) {
	iss := cfg.OIDCIssuers[tok.Issuer]
	switch iss.Type {
	case config.IssuerTypeEmail:
		return challenges.Email(ctx, tok, publicKey, challenge)
	case config.IssuerTypeSpiffe:
		return challenges.Spiffe(ctx, tok, publicKey, challenge)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)
	}
}