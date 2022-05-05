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

package github

import (
	"context"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/identity"
)

type actionsIssuer struct {
	*oidc.IDTokenVerifier
}

func NewActionsIssuer(clientID string) (identity.Issuer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	return &actionsIssuer{
		IDTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (i *actionsIssuer) Match(_ context.Context, url string) bool {
	return url == issuerURL
}

func (i *actionsIssuer) Authenticate(ctx context.Context, token string) (identity.Principal, error) {
	// Authenticate token first by checking ID token signature
	parsed, err := i.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	// Parse claims on authenticated token
	var claims struct {
		JobWorkflowRef string `json:"job_workflow_ref"`
		SHA            string `json:"sha"`
		Trigger        string `json:"event_name"`
		Repository     string `json:"repository"`
		Workflow       string `json:"workflow"`
		Ref            string `json:"ref"`
		// The other fields that are present here seem to depend on the type
		// of workflow trigger that initiated the action.
	}
	if err := parsed.Claims(&claims); err != nil {
		return nil, err
	}

	// Validate that all required claims have been set
	if claims.JobWorkflowRef == "" {
		return nil, errors.New("token missing job_workflow_ref claim")
	}
	if claims.SHA == "" {
		return nil, errors.New("token missing sha claim")
	}
	if claims.Trigger == "" {
		return nil, errors.New("token missing event_name claim")
	}
	if claims.Repository == "" {
		return nil, errors.New("token missing repository claim")
	}
	if claims.Workflow == "" {
		return nil, errors.New("token missing workflow claim")
	}
	if claims.Ref == "" {
		return nil, errors.New("token missing ref claim")
	}

	return &workflowPrincipal{
		url:        "https://github.com/" + claims.JobWorkflowRef,
		sha:        claims.SHA,
		trigger:    claims.Trigger,
		repository: claims.Repository,
		workflow:   claims.Workflow,
		ref:        claims.Ref,
	}, nil
}
