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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	ctclient "github.com/google/certificate-transparency-go/client"
	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Key struct {
	// +required
	Content   []byte `json:"content"`
	Algorithm string `json:"algorithm,omitempty"`
}

type CertificateRequest struct {
	// +required
	PublicKey Key `json:"publicKey"`

	// +required
	SignedEmailAddress []byte `json:"signedEmailAddress"`
}

const (
	signingCertPath = "/api/v1/signingCert"
	rootCertPath    = "/api/v1/rootCert"
)

type api struct {
	ct *ctclient.LogClient
	ca certauth.CertificateAuthority

	*http.ServeMux
}

// New creates a new http.Handler for serving the Fulcio API.
func New(ct *ctclient.LogClient, ca certauth.CertificateAuthority) http.Handler {
	var a api
	a.ServeMux = http.NewServeMux()
	a.HandleFunc(signingCertPath, a.signingCert)
	a.HandleFunc(rootCertPath, a.rootCert)
	a.ct = ct
	a.ca = ca
	return &a
}

func extractIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}
	var payload struct {
		Issuer string `json:"iss"`
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	return payload.Issuer, nil
}

// We do this to bypass needing actual OIDC tokens for unit testing.
var authorize = actualAuthorize

func actualAuthorize(req *http.Request) (*oidc.IDToken, error) {
	// Strip off the "Bearer" prefix.
	token := strings.Replace(req.Header.Get("Authorization"), "Bearer ", "", 1)

	issuer, err := extractIssuer(token)
	if err != nil {
		return nil, err
	}

	verifier, ok := config.FromContext(req.Context()).GetVerifier(issuer)
	if !ok {
		return nil, fmt.Errorf("unsupported issuer: %s", issuer)
	}
	return verifier.Verify(req.Context(), token)
}

func verifyContentType(contentType string) error {
	gotContentType, _, perr := mime.ParseMediaType(contentType)
	if perr != nil {
		return fmt.Errorf("could not parse Content-Type %q", contentType)
	}
	wantContentType := "application/json"
	if gotContentType != wantContentType {
		return fmt.Errorf("signing cert handler must receive %q, got %q", wantContentType, gotContentType)
	}
	return nil
}

func (a *api) signingCert(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		err := fmt.Errorf("signing cert handler must receive POSTs, got %s", req.Method)
		handleFulcioAPIError(w, req, http.StatusMethodNotAllowed, err, err.Error())
		return
	}

	if err := verifyContentType(req.Header.Get("Content-Type")); err != nil {
		handleFulcioAPIError(w, req, http.StatusUnsupportedMediaType, err, err.Error())
		return
	}

	ctx := req.Context()
	logger := log.ContextLogger(ctx)

	principal, err := authorize(req)
	if err != nil {
		handleFulcioAPIError(w, req, http.StatusUnauthorized, err, invalidCredentials)
		return
	}

	// Parse the request body.
	cr := CertificateRequest{}
	if err := json.NewDecoder(req.Body).Decode(&cr); err != nil {
		handleFulcioAPIError(w, req, http.StatusBadRequest, err, invalidCertificateRequest)
		return
	}

	publicKeyBytes := cr.PublicKey.Content
	// try to unmarshal as DER
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		// try to unmarshal as PEM
		logger.Debugf("error parsing public key as DER, trying pem: %v", err.Error())
		publicKey, err = cryptoutils.UnmarshalPEMToPublicKey(publicKeyBytes)
		if err != nil {
			handleFulcioAPIError(w, req, http.StatusBadRequest, err, invalidPublicKey)
			return
		}
	}
	// Validate public key, checking for weak key parameters.
	if err := cryptoutils.ValidatePubKey(publicKey); err != nil {
		handleFulcioAPIError(w, req, http.StatusBadRequest, err, insecurePublicKey)
		return
	}

	subject, err := ExtractSubject(ctx, principal, publicKey, cr.SignedEmailAddress)
	if err != nil {
		handleFulcioAPIError(w, req, http.StatusBadRequest, err, invalidSignature)
		return
	}

	var csc *certauth.CodeSigningCertificate
	var sctBytes []byte
	// For CAs that do not support embedded SCTs or if the CT log is not configured
	if sctCa, ok := a.ca.(certauth.EmbeddedSCTCA); !ok || a.ct == nil {
		// currently configured CA doesn't support pre-certificate flow required to embed SCT in final certificate
		csc, err = a.ca.CreateCertificate(ctx, subject)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				handleFulcioAPIError(w, req, http.StatusBadRequest, err, err.Error())
				return
			}
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			handleFulcioAPIError(w, req, http.StatusInternalServerError, err, genericCAError)
			return
		}

		// submit to CTL
		if a.ct != nil {
			sct, err := a.ct.AddChain(ctx, ctl.BuildCTChain(csc.FinalCertificate, csc.FinalChain))
			if err != nil {
				handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToEnterCertInCTL)
				return
			}
			// convert to AddChainResponse because Cosign expects this struct.
			addChainResp, err := ctl.ToAddChainResponse(sct)
			if err != nil {
				handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToMarshalSCT)
				return
			}
			sctBytes, err = json.Marshal(addChainResp)
			if err != nil {
				handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToMarshalSCT)
				return
			}
		} else {
			logger.Info("Skipping CT log upload.")
		}
	} else {
		precert, err := sctCa.CreatePrecertificate(ctx, subject)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				handleFulcioAPIError(w, req, http.StatusBadRequest, err, err.Error())
				return
			}
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			handleFulcioAPIError(w, req, http.StatusInternalServerError, err, genericCAError)
		}
		// submit precertificate and chain to CT log
		sct, err := a.ct.AddPreChain(ctx, ctl.BuildCTChain(precert.PreCert, precert.CertChain))
		if err != nil {
			handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToEnterCertInCTL)
			return
		}
		csc, err = sctCa.IssueFinalCertificate(ctx, precert, sct)
		if err != nil {
			handleFulcioAPIError(w, req, http.StatusInternalServerError, err, genericCAError)
			return
		}
	}

	metricNewEntries.Inc()

	var ret strings.Builder
	finalPEM, err := csc.CertPEM()
	if err != nil {
		handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToMarshalCert)
		return
	}
	fmt.Fprintf(&ret, "%s", finalPEM)
	if !bytes.HasSuffix(finalPEM, []byte("\n")) {
		fmt.Fprintf(&ret, "\n")
	}

	finalChainPEM, err := csc.ChainPEM()
	if err != nil {
		handleFulcioAPIError(w, req, http.StatusInternalServerError, err, failedToMarshalCert)
		return
	}
	if len(finalChainPEM) > 0 {
		fmt.Fprintf(&ret, "%s", finalChainPEM)
		if !bytes.HasSuffix(finalChainPEM, []byte("\n")) {
			fmt.Fprintf(&ret, "\n")
		}
	}

	// Set the SCT and Content-Type headers, and then respond with a 201 Created.
	if len(sctBytes) != 0 {
		w.Header().Add("SCT", base64.StdEncoding.EncodeToString(sctBytes))
	}
	w.Header().Add("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusCreated)
	// Write the PEM encoded certificate chain to the response body.
	if _, err := w.Write([]byte(strings.TrimSpace(ret.String()))); err != nil {
		logger.Error("Error writing response: ", err)
	}
}

func (a *api) rootCert(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := log.ContextLogger(ctx)

	root, err := a.ca.Root(ctx)
	if err != nil {
		logger.Error("Error retrieving root cert: ", err)
		handleFulcioAPIError(w, req, http.StatusInternalServerError, err, genericCAError)
		return
	}
	w.Header().Add("Content-Type", "application/pem-certificate-chain")
	if _, err := w.Write(root); err != nil {
		logger.Error("Error writing response: ", err)
	}
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
	case config.IssuerTypeURI:
		return challenges.URI(ctx, tok, publicKey, challenge)
	case config.IssuerTypeUsername:
		return challenges.Username(ctx, tok, publicKey, challenge)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)
	}
}
