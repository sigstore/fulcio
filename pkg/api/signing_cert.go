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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/sigstore/fulcio/pkg/log"

	"github.com/coreos/go-oidc"

	"github.com/go-openapi/runtime/middleware"
	fca "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"golang.org/x/net/context"
)

func SigningCertHandler(params operations.SigningCertParams, principal interface{}) middleware.Responder {

	ctx := context.Background()
	key := params.Submitcsr.Pub

	dec, err := base64.StdEncoding.DecodeString(string(key))
	if err != nil {
		return middleware.Error(http.StatusInternalServerError, err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: dec,
		Type:  "PUBLIC KEY",
	})

	userInfo := principal.(*oidc.UserInfo)

	fmt.Println(dec, params.Submitcsr.Proof, userInfo.Email)
	// Check the proof
	if !fca.Check(dec, string(params.Submitcsr.Proof), userInfo.Email) {
		log.Logger.Info("email address was not signed correctly")
		return middleware.Error(http.StatusBadRequest, "email address was not signed correctly")
	}
	// Now issue cert!
	req := fca.Req(userInfo.Email, pemBytes)

	resp, err := fca.Client.CreateCertificate(ctx, req)
	if err != nil {
		log.Logger.Info("error getting cert", err)
		return middleware.Error(http.StatusInternalServerError, err)
	}

	metricNewEntries.Inc()
	return operations.NewSigningCertCreated().WithPayload(&models.SubmitSuccess{Certificate: resp.PemCertificate})
}
