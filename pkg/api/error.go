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
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/mitchellh/mapstructure"

	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
)

const (
	invalidSignature       = "The signature supplied in the request could not be verified"
	failedToEnterCertInCTL = "Error entering certificate in CTL @ '%v'"
	invalidCredentials     = "There was an error processing the credentials for this request"
	genericCAError           = "error communicating with CA backend"
)

func errorMsg(message string, code int) *models.Error {
	return &models.Error{
		Code:    int64(code),
		Message: message,
	}
}

func handleFulcioAPIError(params interface{}, code int, err error, message string, fields ...interface{}) middleware.Responder {
	if message == "" {
		message = http.StatusText(code)
	}

	re := regexp.MustCompile("^(.*)Params$")
	typeStr := fmt.Sprintf("%T", params)
	handler := re.FindStringSubmatch(typeStr)[1]

	logMsg := func(r *http.Request) {
		log.RequestIDLogger(r).Errorw("exiting with error", append([]interface{}{"handler", handler, "statusCode", code, "clientMessage", message, "error", err}, fields...)...)
		paramsFields := map[string]interface{}{}
		if err := mapstructure.Decode(params, &paramsFields); err == nil {
			log.RequestIDLogger(r).Debug(paramsFields)
		}
	}

	switch params := params.(type) {
	case operations.SigningCertParams:
		logMsg(params.HTTPRequest)
		switch code {
		case http.StatusBadRequest:
			return operations.NewSigningCertBadRequest().WithPayload(errorMsg(message, code)).WithContentType("application/json")
		default:
			return operations.NewSigningCertDefault(code).WithPayload(errorMsg(message, code)).WithContentType("application/json")
		}
	default:
		log.Logger.Errorf("unable to find method for type %T; error: %v", params, err)
		return middleware.Error(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
}
