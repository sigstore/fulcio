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

package ctl

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type clientFunc func(ctx context.Context, csc *ca.CodeSigningCertificate) (*CertChainResponse, error)

func (f clientFunc) AddChain(ctx context.Context, csc *ca.CodeSigningCertificate) (*CertChainResponse, error) {
	return f(ctx, csc)
}

func TestWithLogging(t *testing.T) {
	tests := map[string]struct {
		Client         Client
		ExpectedOutput *regexp.Regexp
	}{
		"Error in client should be logged": {
			clientFunc(func(context.Context, *ca.CodeSigningCertificate) (*CertChainResponse, error) {
				return nil, errors.New(`ctl: testing error`)
			}),
			regexp.MustCompile(`ctl: testing error`),
		},
		"Success in client should log information": {
			clientFunc(func(context.Context, *ca.CodeSigningCertificate) (*CertChainResponse, error) {
				return &CertChainResponse{}, nil
			}),
			regexp.MustCompile(`CTL Submission ID Received:`),
		},
	}

	for test, data := range tests {
		t.Run(test, func(t *testing.T) {
			// Given
			observedZapCore, observedLogs := observer.New(zap.InfoLevel)
			observedLogger := zap.New(observedZapCore)
			log.Logger = observedLogger.Sugar()
			client := WithLogging(data.Client, log.Logger)

			csc := ca.CodeSigningCertificate{
				Subject: &challenges.ChallengeResult{},
			}

			// When
			_, _ = client.AddChain(context.Background(), &csc)

			// Then
			for _, entry := range observedLogs.All() {
				if data.ExpectedOutput.MatchString(entry.Message) {
					// We received expected output so the test passes
					return
				}
			}
			// If we got here we didn't match the expected output so test fails
			t.Error("Didn't find expected output in logs: ", observedLogs.All())
		})
	}
}
