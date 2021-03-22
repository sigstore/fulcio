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
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	ct "github.com/google/certificate-transparency-go"
	"github.com/pkg/errors"
	fca "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/spf13/viper"
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
	ctx, _ = context.WithDeadline(ctx, time.Now().Add(20*time.Second))
	parent := viper.GetString("gcp_private_ca_parent")

	// Now issue precert!
	sct, err := issuePrecert(ctx, parent, emailAddress, publicKeyPEM)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, failedToCreatePrecert)
	}
	log.Logger.Info("Successfully issued precert")
	resp, err := issueCert(ctx, sct, parent, emailAddress, publicKeyPEM)
	if err != nil {
		return handleFulcioAPIError(params, http.StatusBadRequest, err, failedToCreateCert)
	}
	log.Logger.Info("Successfully issued certificate based on precert")

	var ret strings.Builder
	fmt.Fprintf(&ret, "%s\n", resp.PemCertificate)
	for _, cert := range resp.PemCertificateChain {
		fmt.Fprintf(&ret, "%s\n", cert)
	}

	// TODO: return SCT and SCT URL
	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String()))
}

func issuePrecert(ctx context.Context, parent, emailAddress string, publicKeyPEM []byte) (*ct.SignedCertificateTimestamp, error) {
	extensions := fca.PoisonExtension()
	precertReq := fca.Req(parent, emailAddress, publicKeyPEM, extensions)
	log.Logger.Infof("requesting precert from %s for %s", parent, emailAddress)

	resp, err := fca.Client().CreateCertificate(ctx, precertReq)
	if err != nil {
		return nil, errors.Wrap(err, "creating precert")
	}

	derBytes, _ := pem.Decode([]byte(resp.GetPemCertificate()))
	precert, err := x509.ParseCertificate(derBytes.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing precert")
	}
	if !precert.IsPrecertificate() {
		return nil, errors.Wrap(err, "precert is not valid")
	}
	// Submit the precert to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", emailAddress)
	sct, err := submitCertToCTL(resp, ct.AddPreChainPath)
	if err != nil {
		return nil, errors.Wrap(err, "submitting precert to CTL")
	}
	metricNewEntries.Inc()
	return sct, nil
}

func issueCert(ctx context.Context, sct *ct.SignedCertificateTimestamp, parent, emailAddress string, publicKeyPEM []byte) (*privatecapb.Certificate, error) {
	extensions, err := fca.SCTListExtensions([]ct.SignedCertificateTimestamp{*sct})
	if err != nil {
		return nil, errors.Wrap(err, "SCT list extensions")
	}
	req := fca.Req(parent, emailAddress, publicKeyPEM, extensions)
	resp, err := fca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "creating cert")
	}

	derBytes, _ := pem.Decode([]byte(resp.GetPemCertificate()))
	cert, err := x509.ParseCertificate(derBytes.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing cert")
	}
	if cert.IsPrecertificate() {
		return nil, errors.Wrap(err, "still have precert")
	}
	// Submit the precert to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", emailAddress)
	if _, err := submitCertToCTL(resp, ct.AddChainPath); err != nil {
		return nil, errors.Wrap(err, "submitting precert to CTL")
	}
	metricNewEntries.Inc()
	return resp, nil
}

func submitCertToCTL(resp *privatecapb.Certificate, apiPath string) (*ct.SignedCertificateTimestamp, error) {
	ctURL := viper.GetString("ct-log-url")
	c := ctl.New(ctURL)
	sct, err := c.Add(resp.GetPemCertificate(), resp.GetPemCertificateChain(), apiPath)
	if err != nil {
		return nil, errors.Wrap(err, "adding prechain to CTL")
	}
	log.Logger.Info("CTL Submission Signature Received: ", sct.Signature)
	log.Logger.Info("CTL Submission ID Received: ", string(sct.LogID.KeyID[:]))
	return sct, nil
}
