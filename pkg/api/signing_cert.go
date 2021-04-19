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
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"

	fca "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/oauthflow"
)

func SigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	// none of the following cases should happen if the authentication path is working correctly; checking to be defensive
	if principal == nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, errors.New("no principal supplied to request"), invalidCredentials)
	}
	emailAddress, emailVerified, err := oauthflow.EmailFromIDToken(principal)
	if !emailVerified {
		return handleFulcioAPIError(params, http.StatusBadRequest, errors.New("email_verified claim was false"), emailNotVerified)
	} else if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidCredentials)
	}

	publicKey := *params.CertificateRequest.PublicKey
	pkixPubKey, err := x509.ParsePKIXPublicKey(*publicKey.Content)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, malformedPublicKey)
	}

	var pk crypto.PublicKey
	var ok bool
	switch *publicKey.Algorithm {
	case models.CertificateRequestPublicKeyAlgorithmEcdsa:
		if pk, ok = pkixPubKey.(*ecdsa.PublicKey); !ok {
			return handleFulcioAPIError(params, http.StatusBadRequest, errors.New("public key is not ECDSA"), malformedPublicKey)
		}
	}
	// Check the proof
	if err := fca.CheckSignature(*publicKey.Algorithm, pk, *params.CertificateRequest.SignedEmailAddress, emailAddress); err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Bytes: *publicKey.Content,
		Type:  "PUBLIC KEY",
	})
	// Now issue cert!

	parent := viper.GetString("gcp_private_ca_parent")

	req := fca.Req(parent, emailAddress, publicKeyPEM)
	log.Logger.Infof("requesting cert from %s for %s", parent, emailAddress)

	resp, err := fca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}

	// Submit to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", emailAddress)
	ctURL := viper.GetString("ct-log-url")
	c := ctl.New(ctURL)
	ct, err := c.AddChain(resp.PemCertificate, resp.PemCertificateChain)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, fmt.Sprintf(failedToEnterCertInCTL, ctURL))
	}
	log.Logger.Info("CTL Submission Signature Received: ", ct.Signature)
	log.Logger.Info("CTL Submission ID Received: ", ct.ID)

	metricNewEntries.Inc()

	var ret strings.Builder
	fmt.Fprintf(&ret, "%s\n", resp.PemCertificate)
	for _, cert := range resp.PemCertificateChain {
		fmt.Fprintf(&ret, "%s\n", cert)
	}

	//TODO: return SCT and SCT URL
	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String()))
}
