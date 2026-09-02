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
//

// Package tlspolicy resolves the configurable TLS policy shared by Fulcio's
// gRPC, HTTP, and duplex serving paths.
package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

// ALPNProtocols advertises HTTP/2 (required by gRPC) ahead of HTTP/1.1 on
// TLS-enabled HTTP and duplex listeners.
var ALPNProtocols = []string{"h2", "http/1.1"}

// DefaultMinVersion is the TLS floor applied when --tls-min-version is unset.
// TLS 1.3 keeps every serving path default-secure; operators fronted by peers
// that cannot negotiate it can lower the floor to 1.2 via --tls-min-version.
const DefaultMinVersion = tls.VersionTLS13

// Policy is the resolved TLS policy for a serving path.
type Policy struct {
	MinVersion uint16
	// CipherSuites restricts the allowed TLS 1.2 suites; nil keeps the
	// crypto/tls default and has no effect on TLS 1.3.
	CipherSuites []uint16
}

var supportedVersions = map[string]uint16{
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func supportedVersionNames() []string {
	names := make([]string, 0, len(supportedVersions))
	for name := range supportedVersions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ParseVersion maps a minimum TLS version string to its crypto/tls constant.
func ParseVersion(v string) (uint16, error) {
	if id, ok := supportedVersions[strings.TrimSpace(v)]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unsupported --tls-min-version %q (supported: %s)", v, strings.Join(supportedVersionNames(), ", "))
}

// ParseCipherSuites resolves cipher suite names to their crypto/tls IDs. Only
// suites reported as secure by crypto/tls are accepted; names must match the
// crypto/tls spelling (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).
func ParseCipherSuites(names []string) ([]uint16, error) {
	byName := make(map[string]uint16, len(tls.CipherSuites()))
	for _, c := range tls.CipherSuites() {
		byName[c.Name] = c.ID
	}
	var ids []uint16
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		id, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown or insecure --tls-cipher-suites entry %q", n)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Resolve builds a Policy from raw flag values. An empty minVersion selects
// DefaultMinVersion.
func Resolve(minVersion string, cipherSuites []string) (Policy, error) {
	p := Policy{MinVersion: DefaultMinVersion}
	if minVersion != "" {
		mv, err := ParseVersion(minVersion)
		if err != nil {
			return Policy{}, err
		}
		p.MinVersion = mv
	}
	if len(cipherSuites) > 0 {
		cs, err := ParseCipherSuites(cipherSuites)
		if err != nil {
			return Policy{}, err
		}
		p.CipherSuites = cs
	}
	return p, nil
}
