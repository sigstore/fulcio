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
	"context"

	"github.com/sigstore/fulcio/pkg/ca/googleca"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"

	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/log"
)

func GoogleCASigningCertHandler(ctx context.Context, subj *challenges.ChallengeResult, publicKey []byte) (string, []string, error) {
	logger := log.ContextLogger(ctx)

	parent := viper.GetString("gcp_private_ca_parent")

	// call a new function here to set the type, we may need to pass back the issuer?
	var privca *privatecapb.CertificateConfig_SubjectConfig
	switch subj.TypeVal {
	case challenges.EmailValue:
		privca = googleca.EmailSubject(subj.Value)
	case challenges.SpiffeValue:
		privca = googleca.SpiffeSubject(subj.Value)
	case challenges.GithubWorkflowValue:
		privca = googleca.GithubWorkflowSubject(subj.Value)
	case challenges.KubernetesValue:
		privca = googleca.KubernetesSubject(subj.Value)
	}

	extensions := googleca.IssuerExtension(subj.Issuer)
	req := googleca.Req(parent, privca, publicKey, extensions)
	logger.Infof("requesting cert from %s for %v", parent, Subject)

	resp, err := googleca.Client().CreateCertificate(ctx, req)
	if err != nil {
		return "", nil, err
	}
	return resp.PemCertificate, resp.PemCertificateChain, nil
}
