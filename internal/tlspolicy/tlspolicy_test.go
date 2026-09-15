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

package tlspolicy

import (
	"crypto/tls"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"  1.3  ", tls.VersionTLS13, false},
		{"1.1", 0, true},
		{"1.0", 0, true},
		{"TLS1.2", 0, true},
		{"VersionTLS12", 0, true},
		{"garbage", 0, true},
	}
	for _, tc := range tests {
		got, err := ParseVersion(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseVersion(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseVersion(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

func TestParseCipherSuites(t *testing.T) {
	// A known-secure TLS 1.2 suite reported by tls.CipherSuites().
	secure := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

	t.Run("valid suites", func(t *testing.T) {
		ids, err := ParseCipherSuites([]string{secure})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 1 || ids[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Fatalf("unexpected ids: %v", ids)
		}
	})

	t.Run("blank entries skipped", func(t *testing.T) {
		ids, err := ParseCipherSuites([]string{"", "  ", secure})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("expected 1 id, got %v", ids)
		}
	})

	t.Run("unknown suite rejected", func(t *testing.T) {
		if _, err := ParseCipherSuites([]string{"NOT_A_REAL_SUITE"}); err == nil {
			t.Fatal("expected error for unknown suite")
		}
	})

	t.Run("insecure suite rejected", func(t *testing.T) {
		// Present only in tls.InsecureCipherSuites(), so it must be rejected.
		if _, err := ParseCipherSuites([]string{"TLS_RSA_WITH_AES_128_CBC_SHA"}); err == nil {
			t.Fatal("expected insecure suite to be rejected")
		}
	})
}

func TestResolve(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		p, err := Resolve("", nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %#x, want default %#x", p.MinVersion, tls.VersionTLS13)
		}
		if p.CipherSuites != nil {
			t.Errorf("CipherSuites = %v, want nil", p.CipherSuites)
		}
	})

	t.Run("override min and ciphers", func(t *testing.T) {
		p, err := Resolve("1.2", []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
		if err != nil {
			t.Fatal(err)
		}
		if p.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %#x, want %#x", p.MinVersion, tls.VersionTLS12)
		}
		if len(p.CipherSuites) != 1 {
			t.Errorf("CipherSuites = %v, want one entry", p.CipherSuites)
		}
	})

	t.Run("invalid min version errors", func(t *testing.T) {
		if _, err := Resolve("1.1", nil); err == nil {
			t.Fatal("expected error for unsupported version")
		}
	})

	t.Run("invalid cipher suite errors", func(t *testing.T) {
		if _, err := Resolve("", []string{"NOT_A_REAL_SUITE"}); err == nil {
			t.Fatal("expected error for unknown cipher suite")
		}
	})
}
