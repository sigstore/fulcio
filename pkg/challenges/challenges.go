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

package challenges

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/identity/buildkite"
	"github.com/sigstore/fulcio/pkg/identity/email"
	"github.com/sigstore/fulcio/pkg/identity/generic"
	"github.com/sigstore/fulcio/pkg/identity/github"
	"github.com/sigstore/fulcio/pkg/identity/gitlabcom"
	"github.com/sigstore/fulcio/pkg/identity/kubernetes"
	"github.com/sigstore/fulcio/pkg/identity/spiffe"
	"github.com/sigstore/fulcio/pkg/identity/uri"
	"github.com/sigstore/fulcio/pkg/identity/username"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// CheckSignature verifies a challenge, a signature over the subject or email
// of an OIDC token
func CheckSignature(pub crypto.PublicKey, proof []byte, subject string) error {
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	return verifier.VerifySignature(bytes.NewReader(proof), strings.NewReader(subject))
}

func PrincipalFromIDToken(ctx context.Context, tok *oidc.IDToken) (identity.Principal, error) {
	iss, ok := config.FromContext(ctx).GetIssuer(tok.Issuer)
	if !ok {
		return nil, fmt.Errorf("configuration can not be loaded for issuer %v", tok.Issuer)
	}
	var principal identity.Principal
	var err error
	switch iss.Type {
	case config.IssuerTypeCiProvider:
		principal, err = generic.WorkflowPrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeBuildkiteJob:
		principal, err = buildkite.JobPrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeGitLabPipeline:
		principal, err = gitlabcom.JobPrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeEmail:
		principal, err = email.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeSpiffe:
		principal, err = spiffe.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeGithubWorkflow:
		principal, err = github.WorkflowPrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeKubernetes:
		principal, err = kubernetes.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeURI:
		principal, err = uri.PrincipalFromIDToken(ctx, tok)
	case config.IssuerTypeUsername:
		principal, err = username.PrincipalFromIDToken(ctx, tok)
	default:
		return nil, fmt.Errorf("unsupported issuer: %s", iss.Type)

	}
	if err != nil {
		return nil, err
	}

	return principal, nil
}

// ParsePublicKey parses a PEM or DER encoded public key. Returns an error if
// decoding fails or if no public key is found.
func ParsePublicKey(encodedPubKey string) (crypto.PublicKey, error) {
	if len(encodedPubKey) == 0 {
		return nil, errors.New("public key not provided")
	}
	// try to unmarshal as PEM
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(encodedPubKey))
	if err != nil {
		// try to unmarshal as DER
		publicKey, err = x509.ParsePKIXPublicKey([]byte(encodedPubKey))
		if err != nil {
			return nil, errors.New("error parsing PEM or DER encoded public key")
		}
	}
	return publicKey, err
}
