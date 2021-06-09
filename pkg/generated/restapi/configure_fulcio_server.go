// This file is safe to edit. Once it exists it will not be overwritten

// /*
// Copyright The Fulcio Authors.
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
// */
//

package restapi

import (
	"context"
	"crypto/tls"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/spf13/viper"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/middleware"
	goaerrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/cors"

	pkgapi "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
	"github.com/sigstore/fulcio/pkg/log"
)

//go:generate swagger generate server --target ../../generated --name FulcioServer --spec ../../../openapi.yaml --principal interface{} --exclude-main

func configureFlags(api *operations.FulcioServerAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.FulcioServerAPI) http.Handler {
	// configure the api here
	api.ServeError = logAndServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	api.Logger = log.Logger.Infof

	// api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()
	api.ApplicationPemCertificateChainProducer = runtime.TextProducer()

	// OIDC objects used for authentication
	fulcioCfg := config.Config()

	verifierMap := map[string]*oidc.IDTokenVerifier{}
	for _, iss := range fulcioCfg.OIDCIssuers {
		provider, err := oidc.NewProvider(context.Background(), iss.IssuerURL)
		if err != nil {
			log.Logger.Fatal(err)
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: iss.ClientID})
		verifierMap[iss.IssuerURL] = verifier

	}
	api.BearerAuth = func(token string) (*oidc.IDToken, error) {

		token = strings.Replace(token, "Bearer ", "", 1)

		errs := []string{}
		var idToken *oidc.IDToken
		for _, verifier := range verifierMap {
			tok, err := verifier.Verify(context.Background(), token)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			idToken = tok
			break
		}

		if idToken == nil {
			return nil, goaerrors.New(http.StatusUnauthorized, strings.Join(errs, ","))
		}
		if _, ok, err := oauthflow.EmailFromIDToken(idToken); !ok || err != nil {
			if err != nil {
				return nil, goaerrors.New(http.StatusUnauthorized, err.Error())
			}
			return nil, goaerrors.New(http.StatusUnauthorized, "email has not been verified with token issuer")
		}

		return idToken, nil
	}

	// Select which CA / KMS system to use
	// Currently supported:
	// googleca: Google Certficate Authority Service
	// fulcio: Generic PKCS11 / HSM backed service
	CAType := viper.GetString("ca")
	switch CAType {
	case "googleca":
		api.SigningCertHandler = operations.SigningCertHandlerFunc(pkgapi.GoogleSigningCertHandler)
	case "fulcioca":
		api.SigningCertHandler = operations.SigningCertHandlerFunc(pkgapi.FulcioSigningCertHandler)
	default:
		api.SigningCertHandler = operations.SigningCertHandlerFunc(pkgapi.GoogleSigningCertHandler)
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	api.AddMiddlewareFor("POST", "/api/v1/signingCert", middleware.NoCache)

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// We need this type to act as an adapter between zap and the middleware request logger.
type logAdapter struct {
}

func (l *logAdapter) Print(v ...interface{}) {
	log.Logger.Info(v...)
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	middleware.DefaultLogger = middleware.RequestLogger(
		&middleware.DefaultLogFormatter{Logger: &logAdapter{}})
	returnHandler := middleware.Logger(handler)
	returnHandler = middleware.Recoverer(returnHandler)
	returnHandler = middleware.Heartbeat("/ping")(returnHandler)

	handleCORS := cors.Default().Handler
	returnHandler = handleCORS(returnHandler)

	returnHandler = wrapMetrics(returnHandler)

	return middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		r = r.WithContext(log.WithRequestID(ctx, middleware.GetReqID(ctx)))
		defer func() {
			_ = log.RequestIDLogger(r).Sync()
		}()

		returnHandler.ServeHTTP(w, r)
	}))
}

func wrapMetrics(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		defer func() {
			// This logs latency broken down by URL path and response code
			pkgapi.MetricLatency.With(map[string]string{
				"path": r.URL.Path,
				"code": strconv.Itoa(ww.Status()),
			}).Observe(float64(time.Since(start)))
		}()

		handler.ServeHTTP(ww, r)

	})
}

func logAndServeError(w http.ResponseWriter, r *http.Request, err error) {
	log.RequestIDLogger(r).Error(err)
	requestFields := map[string]interface{}{}
	if err := mapstructure.Decode(r, &requestFields); err == nil {
		log.RequestIDLogger(r).Debug(requestFields)
	}
	// errors should always be in JSON
	w.Header()["Content-Type"] = []string{"application/json"}
	if e, ok := err.(goaerrors.Error); ok && e.Code() == http.StatusUnauthorized {
		fulcioCfg := config.Config()
		// this is set directly so the header name is not canonicalized
		issuers := []string{}
		for iss := range fulcioCfg.OIDCIssuers {
			issuers = append(issuers, "Bearer realm=\""+iss+"\",scope=\"openid email\"")
		}
		w.Header()["WWW-Authenticate"] = []string{strings.Join(issuers, ", ")}
		w.WriteHeader(int(e.Code()))
		// mask actual auth reason from client
		err = goaerrors.New(e.Code(), "authentication credentials could not be validated")
	}
	goaerrors.ServeError(w, r, err)
}
