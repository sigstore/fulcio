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

package identity

import "context"

type Issuer interface {
	// Match checks if this issuer can authenticate tokens from a given issuer URL
	Match(ctx context.Context, url string) bool

	// Authenticate ID token and return Principal on success. The ID token's signature
	// is verified in the call -- invalid signature must result in an error.
	Authenticate(ctx context.Context, token string) (Principal, error)
}
