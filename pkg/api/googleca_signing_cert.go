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
	"fmt"

	"github.com/spf13/viper"

	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/log"
)

func GoogleCASigningCertHandler(ctx context.Context, subj *challenges.ChallengeResult, publicKey []byte) (string, []string, error) {
	logger := log.ContextLogger(ctx)

	version := viper.GetString("gcp_private_ca_version")

	logger.Infof("using privateca api version %v", version)

	switch version {
	case "v1":
		return GoogleCASigningCertHandlerV1(ctx, subj, publicKey)
	case "v1beta1":
		return GoogleCASigningCertHandlerV1Beta1(ctx, subj, publicKey)
	}
	panic(fmt.Errorf("unknown gcp private ca version: %v", version))
}
