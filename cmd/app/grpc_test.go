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
//

package app

import (
	"os"
	"path/filepath"
	"testing"
)

const keyPEM = `-----BEGIN PRIVATE KEY-----
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
qYtj1Qkj5x+/YNNEPPyaPZ54nh3F
-----END PRIVATE KEY-----`

const certPEM = `-----BEGIN CERTIFICATE-----
MIIFqzCCA5OgAwIBAgIUTmTZD9FuR4UNUNVOkB2IMeWqv1UwDQYJKoZIhvcNAQEL
BQAwZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGFu
ZDERMA8GA1UECgwIU2lnc3RvcmUxDzANBgNVBAsMBkZ1bGNpbzESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIzMDYyODAwMTQzMloXDTMzMDYyNTAwMTQzMlowZTELMAkG
A1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGFuZDERMA8GA1UE
CgwIU2lnc3RvcmUxDzANBgNVBAsMBkZ1bGNpbzESMBAGA1UEAwwJbG9jYWxob3N0
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvc3MNQYRO5ytG+8FsPn5
0Z8koUG4sYPf6ZLTMP78+sRYfz2ggZaP46Hl3f571AB8nXSBRbIc9byDgOVpOs9t
zRnYA6tyv9cgtOCtgFfuctHFdeWpJXQr4wWhB0oUspmu66cmFKYfdwrfnrjvRkZ2
+33fGK0hC6EXtNIX7sg+Y98jT1iW0AIiBZxMBf8p5d5fTEfodVN/NZ0FN58/TOPO
jmkStqta+fZrPL02TVZ/IdDx7RSWVqD+KcqOJdSneuCt5qniQgcLwBMIk5ymyMLP
+yKl1GQXHfagxh3e84HlE93XgVCThk9XK8HSQerUmH0oklIx2PgcSS0FPjsz49Us
Kd7QweZAzcaaaoapK0QkXRvUZLSwPgOjriJtd6Pi5S7xN91DnGmyDHA7BGgCtew7
1BUgW2AzWXJq3EX0kHjMaEgHCL59SUw/pOlMiNXMC6hnUSH5lnY2isNs9+DUU+Xa
/Z9ME+B0SiRCaRGq7ZUdXiHuaN+DiRj3hX1VO96wVjvZAh0JklI6pVB7cz6HvOwx
iAtSiXxqIQZkyac3lP939tAFzLVvpqSqaHzUF8bqBSkWxy8iZVW9EJiIb8wAVE8R
Sl4WssnUrneMfXjxsyQ271H6DIDLWP4BHtorqcN0vGnOE37N6DjrOJaaTyaThn2q
Kjmt6ghqvTY0CRVpyQz3szUCAwEAAaNTMFEwHQYDVR0OBBYEFGgoph9DIwXUHUT0
8y7CtcviGmPhMB8GA1UdIwQYMBaAFGgoph9DIwXUHUT08y7CtcviGmPhMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAIzLEKyA1KAEgHmH4/gipKct
qMYfmTPTgKm3s5sEQlFZVQS9BzjgAnHq943JDn/GqPOipAZUw3iE3sueZSVypwEi
zSjbJTPJPZn4Z/RcTK8ovtjVJDUUPxAe9ScpA8YShcwcITxiXt+CzLm4lSs67kDP
BqOSfrjnCSazjtFJnTEpysynTe9B8hD9ODWm4k+/hh+PGB3fqi7ZJm0+9fMr86lR
QW6ZMvwUXfWUVCfalOINk17Z42hXk4+jhj8mjnMtflt9o4xPdSl3qkVwoUFRCwfy
RMYL+gaKONClOogxa/sMgqycENH31DJX+lPwXUFQ+bH2SKnz3+Dgmds5O8EgheUL
BDQ1Tbz7d4MTAgo/ZefZE94ZBfcz6KNwgTcxlLfl3mBc5bxhri8Y1aR8tlhOV5JS
hRa/vAPlpdglBFTO0wThjJEy0xlGlUQgQ1Y1HrqATOO6ACxkbX7DEouezRe0q6e5
VOUjno7qtSq6Sgj5ufWaI3qyZhJtCa0db1p6xnjIzwCblhrFKtJObqQI1Rr02Wz+
H165IZ5Lwe4VyrYGTPJTzK8f0NmwVGcgB0llNi8jdmKuLc/MWuBkKdW0FtUksfzv
tSLmTWsb+j/Oxljalf+rAlItYk297HN0xMvlkHkB80O5Un6OMCHAjJmfOVZal2Y5
o4ZDR+PzKEbU8eUQbooS
-----END CERTIFICATE-----`

func TestCreateGRPCCreds(t *testing.T) {
	dir := t.TempDir()

	// not PKI material
	bad := []byte("not PKI material")
	badPath := filepath.Join(dir, "bad.pem")
	os.WriteFile(badPath, bad, 0644)

	// priv key
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(keyPath, []byte(keyPEM), 0644)

	// cert
	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, []byte(certPEM), 0644)

	type testCase struct {
		desc     string
		keyPath  string
		certPath string
		success  bool
	}

	testCases := []testCase{
		{
			desc:     "invalid path",
			keyPath:  filepath.Join(dir, "not_here"),
			certPath: badPath,
			success:  false,
		},
		{
			desc:     "invalid key and cert",
			keyPath:  badPath,
			certPath: badPath,
			success:  false,
		},
		{
			desc:     "invalid key, valid cert",
			keyPath:  badPath,
			certPath: certPath,
			success:  false,
		},
		{
			desc:     "valid key, invalid cert",
			keyPath:  keyPath,
			certPath: badPath,
			success:  false,
		},
		{
			desc:     "valid key, valid cert",
			keyPath:  keyPath,
			certPath: certPath,
			success:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := createGRPCCreds(tc.certPath, tc.keyPath)
			if tc.success != (err == nil) {
				t.Errorf("unexpected result: %v", err)
			}
		})
	}
}
