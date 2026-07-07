// Copyright 2026 The Sigstore Authors.
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

package server

import (
	"context"
	"errors"
	"testing"

	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/sigstore/fulcio/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
)

func TestHandleFulcioGRPCError_RspError(t *testing.T) {
	// Setup observer logger to capture logs
	core, recorded := observer.New(zap.DebugLevel)
	observedLogger := zap.New(core).Sugar()

	// Save original logger and restore after test
	origLogger := log.Logger
	log.Logger = observedLogger
	defer func() { log.Logger = origLogger }()

	// Create a client.RspError
	rspErr := ctclient.RspError{
		Err:        errors.New("some ct error"),
		StatusCode: 400,
		Body:       []byte("detailed error message from CT log"),
	}

	ctx := context.Background()
	_ = handleFulcioGRPCError(ctx, codes.Internal, rspErr, "test message")

	// Verify logs
	if recorded.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", recorded.Len())
	}

	logEntry := recorded.All()[0]
	if logEntry.Message != rspErr.Error() {
		t.Errorf("expected log message to be %q, got %q", rspErr.Error(), logEntry.Message)
	}

	// Check if "body" field is present in context fields
	var foundBody bool
	for _, field := range logEntry.Context {
		if field.Key == "body" {
			foundBody = true
			if field.String != "detailed error message from CT log" {
				t.Errorf("expected body field to be %q, got %q", "detailed error message from CT log", field.String)
			}
		}
	}
	if !foundBody {
		t.Error("expected 'body' field in log context, but not found")
	}
}

func TestHandleFulcioGRPCError_NormalError(t *testing.T) {
	core, recorded := observer.New(zap.DebugLevel)
	observedLogger := zap.New(core).Sugar()

	origLogger := log.Logger
	log.Logger = observedLogger
	defer func() { log.Logger = origLogger }()

	normalErr := errors.New("normal error")

	ctx := context.Background()
	_ = handleFulcioGRPCError(ctx, codes.Internal, normalErr, "test message")

	if recorded.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", recorded.Len())
	}

	logEntry := recorded.All()[0]
	for _, field := range logEntry.Context {
		if field.Key == "body" {
			t.Error("unexpected 'body' field in log context for normal error")
		}
	}
}
