// Copyright 2023 The Sigstore Authors.
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

package base

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/fulcio/pkg/identity"
)

var (
	// For testing
	CmpOptions = cmpopts.IgnoreUnexported(baseIssuer{})
)

type baseIssuer struct {
	issuerURL string
}

func Issuer(issuerURL string) identity.Issuer {
	return &baseIssuer{issuerURL: issuerURL}
}

// This is unimplemented for the base issuer, and should be implemented unique to each issuer
func (e *baseIssuer) Authenticate(_ context.Context, token string) (identity.Principal, error) { //nolint: revive
	return nil, fmt.Errorf("unimplemented")
}

// Match is the same across issuers, so it doesn't need to be implemented anywhere else
func (e *baseIssuer) Match(_ context.Context, url string) bool {
	if url == e.issuerURL {
		return true
	}
	// If this is a MetaIssuer the issuer URL could be a regex
	// Check if the regex is valid against the provided url
	re, err := metaRegex(e.issuerURL)
	if err != nil {
		return false
	}
	return re.MatchString(url)
}

func metaRegex(issuer string) (*regexp.Regexp, error) {
	// Quote all of the "meta" characters like `.` to avoid
	// those literal characters in the URL matching any character.
	// This will ALSO quote `*`, so we replace the quoted version.
	quoted := regexp.QuoteMeta(issuer)

	// Replace the quoted `*` with a regular expression that
	// will match alpha-numeric parts with common additional
	// "special" characters.
	replaced := strings.ReplaceAll(quoted, regexp.QuoteMeta("*"), "[-_a-zA-Z0-9]+")

	// Compile into a regular expression.
	return regexp.Compile(replaced)
}
