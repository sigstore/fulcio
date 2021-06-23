package api

import (
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/viper"
	"net/http"
	"strings"
)


func SigningCertHandler(params operations.SigningCertParams, principal *oidc.IDToken) middleware.Responder {
	ctx := params.HTTPRequest.Context()

    //none of the following cases should happen if the authentication path is working correctly; checking to be defensive
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

	var PemCertificate string
	var PemCertificateChain []string
	switch viper.GetString("ca") {
	case "googleca":
		PemCertificate, PemCertificateChain, err = GoogleCASigningCertHandler(ctx, *subj, publicKeyPEM)
	default:
		panic("sort this later!")
	}

	// Submit to CTL
	log.Logger.Info("Submitting CTL inclusion for OIDC grant: ", subject)
	ctURL := viper.GetString("ct-log-url")
	if ctURL != "" {
		c := ctl.New(ctURL)
		ct, err := c.AddChain(PemCertificate, PemCertificateChain)
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
	fmt.Fprintf(&ret, "%s\n", PemCertificate)
	for _, cert := range PemCertificateChain {
		fmt.Fprintf(&ret, "%s\n", cert)
	}


	return operations.NewSigningCertCreated().WithPayload(strings.TrimSpace(ret.String()))

}
