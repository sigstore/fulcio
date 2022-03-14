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

package ctl

import (
	"context"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/log"
	"go.uber.org/zap"
)

type ctlLoggingClient struct {
	next   Client
	logger *zap.SugaredLogger
}

func (lc *ctlLoggingClient) AddChain(ctx context.Context, csc *ca.CodeSigningCertificate) (*CertChainResponse, error) {
	logger := log.ContextLogger(ctx)
	logger.Info("Submitting CTL inclusion for subject: ", csc.Subject.Value)
	resp, err := lc.next.AddChain(ctx, csc)
	if err != nil {
		logger.Error("Failed to submit certificate to CTL with error: ", err)
		return nil, err
	}
	logger.Info("CTL Submission Signature Received: ", resp.Signature)
	logger.Info("CTL Submission ID Received: ", resp.ID)
	return resp, nil
}

// WithLogging adds logging (in the writing helpful information to console
// sense) to a certificate transparenct log client
func WithLogging(next Client, logger *zap.SugaredLogger) Client {
	return &ctlLoggingClient{next, logger}
}
