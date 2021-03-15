/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	fca "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/spf13/viper"
)

func SigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	emailAddress, _, _ := oauthflow.EmailFromIDToken(principal)

	publicKey := *params.CertificateRequest.PublicKey
	pkixPubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, malformedPublicKey)
	}
	ecdsaPubKey, ok := pkixPubKey.(*ecdsa.PublicKey)
	if !ok {
		return handleFulcioAPIError(params, http.StatusBadRequest, errors.New("public key is not ECDSA"), malformedPublicKey)
	}

	// Check the proof
	if err := fca.CheckSignature(ecdsaPubKey, *params.CertificateRequest.SignedEmailAddress, emailAddress); err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, invalidSignature)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Bytes: publicKey,
		Type:  "PUBLIC KEY",
	})
	// Now issue cert!
	req := fca.Req(emailAddress, publicKeyPEM)

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
