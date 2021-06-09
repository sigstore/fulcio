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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/ca/fulcioca"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/sigstore/fulcio/pkg/pkcs11"
)

func FulcioCASigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {

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

	// Perform a proof challenge verification
	if err := fulcioca.CheckSignature(pkixPubKey, *params.CertificateRequest.SignedEmailAddress, emailAddress); err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	// Use a generic Cert failure message as we don't want to tell the client about a HSM failure and risk exposure of
	// internal security controls
	p11Ctx, err := pkcs11.InitHSMCtx()
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}
	defer p11Ctx.Close()

	rootID := []byte(viper.GetString("hsm-caroot-id"))

	// get the existing root CA from the HSM
	rootCA, err := p11Ctx.FindCertificate(rootID, nil, nil)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}

	// get the private key object from HSM
	privKey, err := p11Ctx.FindKeyPair(nil, []byte("FulcioCA"))
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}

	// Generate the client signing certificate

	clientCert, err := fulcioca.CreateClientCertificate(rootCA, emailAddress, pkixPubKey, privKey)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusInternalServerError, err, failedToCreateCert)
	}

	// Format in PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert,
	})

	// Format in PEM
	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCA.Raw,
	})

	// Submit to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", subject)
	ctURL := viper.GetString("ct-log-url")
	if ctURL != "" {
		c := ctl.New(ctURL)
		ct, err := c.AddChain(string(certPEM),[]string{string(rootPEM)})
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
	fmt.Fprintf(&ret, "%s\n", string(certPEM))
	for _, cert := range []string{string(rootPEM)} {
		fmt.Fprintf(&ret, "%s\n", cert)
	}

	//TODO: return SCT and SCT URL
	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String()))
}
