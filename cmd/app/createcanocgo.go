//go:build !cgo

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

package app

import (
	"github.com/sigstore/fulcio/pkg/log"
	"github.com/spf13/cobra"
)

// Just a placeholder for erroring with a meaningful message if the
// binary has been built with GCO_ENABLED=0 tags.
func newCreateCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "createca",
		Short: "Create a root CA in a pkcs11 device (**not supported in this binary**)",
		Long: `Create an x509 root CA within a pkcs11 device using values
such as organization, country etc. This can then be used as the root
certificate authority for an instance of sigstore fulcio`,
		Run: runCreateCACmdPlaceholder,
	}
}

func runCreateCACmdPlaceholder(cmd *cobra.Command, args []string) {
	log.Logger.Fatal("Binary has been built with CGO_ENABLED=0, createca is not supported")
}
