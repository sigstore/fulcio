// Copyright 2022 The Sigstore Authors.
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

package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/api"
	gw "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type httpServer struct {
	*http.Server
	httpServerEndpoint string
}

func extractOIDCTokenFromAuthHeader(ctx context.Context, req *http.Request) metadata.MD {
	token := strings.Replace(req.Header.Get("Authorization"), "Bearer ", "", 1)
	return metadata.Pairs(api.MetadataOIDCTokenKey, token)
}

func alterJSONResponse(ctx context.Context, rw http.ResponseWriter, msg protoreflect.ProtoMessage) error {
	if m, ok := msg.(*gw.CertificateResponse); ok {
		rw.Header().Set("Content-Type", "application/pem-certificate-chain")
		rw.Header().Del("Grpc-Metadata-Content-Type")
		if len(m.SignedCertificateTimestamp) > 0 {
			rw.Header().Set("SCT", base64.StdEncoding.EncodeToString(m.SignedCertificateTimestamp))
		}
		rw.WriteHeader(http.StatusCreated)
	} else if _, ok := msg.(*gw.RootCertificateResponse); ok {
		rw.Header().Set("Content-Type", "application/pem-certificate-chain")
		rw.Header().Del("Grpc-Metadata-Content-Type")
	}
	return nil
}

type PEMMarshaller struct {
	defaultMarshaller runtime.Marshaler
}

// Marshal marshals "v" into byte sequence.
func (p *PEMMarshaller) Marshal(v interface{}) ([]byte, error) {
	switch msg := v.(type) {
	case *gw.CertificateResponse:
		return []byte(msg.Certificate), nil
	case *gw.RootCertificateResponse:
		return []byte(msg.Certificate), nil
	}
	return p.defaultMarshaller.Marshal(v)
}

// Unmarshal unmarshals "data" into "v". "v" must be a pointer value.
func (p PEMMarshaller) Unmarshal(data []byte, v interface{}) error {
	return p.defaultMarshaller.Unmarshal(data, v)
}

// NewDecoder returns a Decoder which reads byte sequence from "r".
func (p PEMMarshaller) NewDecoder(r io.Reader) runtime.Decoder {
	return p.defaultMarshaller.NewDecoder(r)
}

// NewEncoder returns an Encoder which writes bytes sequence into "w".
func (p PEMMarshaller) NewEncoder(w io.Writer) runtime.Encoder {
	return p.defaultMarshaller.NewEncoder(w)
}

// ContentType returns the Content-Type which this marshaler is responsible for.
func (p PEMMarshaller) ContentType(v interface{}) string {
	switch v.(type) {
	case *gw.CertificateResponse, *gw.RootCertificateResponse:
		return "application/pem-certificate-chain"
	}
	return "application/json"
}

func createHTTPServer(ctx context.Context, grpcServer *grpcServer) httpServer {
	defaultMux := runtime.NewServeMux()
	_, defaultOutboundMarshaller := runtime.MarshalerForRequest(defaultMux, &http.Request{})

	mux := runtime.NewServeMux(runtime.WithMetadata(extractOIDCTokenFromAuthHeader),
		runtime.WithForwardResponseOption(alterJSONResponse),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &PEMMarshaller{defaultOutboundMarshaller}))

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := gw.RegisterCAHandlerFromEndpoint(ctx, mux, grpcServer.grpcServerEndpoint, opts); err != nil {
		log.Logger.Fatal(err)
	}

	// Limit request size
	handler := api.WithMaxBytes(mux, maxMsgSize)
	httpServerEndpoint := fmt.Sprintf("%s:%s", viper.GetString("http-host"), viper.GetString("http-port"))

	api := http.Server{
		Addr:    httpServerEndpoint,
		Handler: handler,

		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return httpServer{&api, httpServerEndpoint}
}

func (h httpServer) startListener() {
	log.Logger.Infof("listening on http at %s", h.httpServerEndpoint)
	go func() {
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Logger.Fatal(err)
		}
	}()
}
