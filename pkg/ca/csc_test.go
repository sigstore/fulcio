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

package ca

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestCreateCSCFromDER(t *testing.T) {
	tests := map[string]struct {
		CertificatePEM string
		ChainPEM       []string
		WantErr        bool
	}{
		"Good certificate chain should parse without error": {
			CertificatePEM: `-----BEGIN CERTIFICATE-----
MIICFDCCAZmgAwIBAgIUAPsd9CUVr9TNG8nRzYHJrC/ZjtowCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MTExNjI4MjRaFw0yMjA1MTExNjM4MjNaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATGZIJr9odbCYVecVDp9LB1Ye9ehw7tCvPphaKQY832ftnRYFluAb6G
TtsmHqms4TXsTbvKHFJ9IxtvS6m2uJ6ao4HGMIHDMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTAROUd
EzzWfUH12GTQKrm84cGngTAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF
+jAjBgNVHREBAf8EGTAXgRVuYXRoYW5AY2hhaW5ndWFyZC5kZXYwKQYKKwYBBAGD
vzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMAoGCCqGSM49BAMDA2kA
MGYCMQDUnEwydrGWXaMdhE4JXvNAxAPI6iZzDFZAmqTsOyeSV1LWeFQIgrOGHQwB
ObpE85YCMQCNhS9zht0xv7j2FGuLshR3aLMTzY3UFBC3pEcI+yy4hI12MHh4laKT
yhW8MpHgDWs=
-----END CERTIFICATE-----`,
			ChainPEM: []string{
				`-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`,
			},
			WantErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var certDer []byte
			{
				buf := []byte(test.CertificatePEM)
				block, _ := pem.Decode(buf)
				if block == nil {
					t.Fatal("bad certificate format")
				}
				certDer = block.Bytes
			}

			chainBytes := []byte(strings.Join(test.ChainPEM, ""))
			chain, err := cryptoutils.UnmarshalCertificatesFromPEM(chainBytes)
			if err != nil {
				t.Fatal("bad ca chain format")
			}

			csc, err := CreateCSCFromDER(certDer, chain)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
				return
			}

			gotCert, err := csc.CertPEM()
			if err != nil {
				t.Error(err)
			}
			if diff := cmp.Diff(gotCert, test.CertificatePEM); diff != "" {
				t.Error(diff)
			}

			gotChain, err := csc.ChainPEM()
			if err != nil {
				t.Error(err)
			}
			if diff := cmp.Diff(gotChain, test.ChainPEM); diff != "" {
				t.Error(diff)
			}
		})
	}
}
func TestCreateCSCFromPEM(t *testing.T) {
	tests := map[string]struct {
		CertificatePEM string
		ChainPEM       []string
		WantErr        bool
	}{
		"Good certificate chain should parse without error": {
			CertificatePEM: `-----BEGIN CERTIFICATE-----
MIICFDCCAZmgAwIBAgIUAPsd9CUVr9TNG8nRzYHJrC/ZjtowCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MTExNjI4MjRaFw0yMjA1MTExNjM4MjNaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATGZIJr9odbCYVecVDp9LB1Ye9ehw7tCvPphaKQY832ftnRYFluAb6G
TtsmHqms4TXsTbvKHFJ9IxtvS6m2uJ6ao4HGMIHDMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTAROUd
EzzWfUH12GTQKrm84cGngTAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF
+jAjBgNVHREBAf8EGTAXgRVuYXRoYW5AY2hhaW5ndWFyZC5kZXYwKQYKKwYBBAGD
vzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMAoGCCqGSM49BAMDA2kA
MGYCMQDUnEwydrGWXaMdhE4JXvNAxAPI6iZzDFZAmqTsOyeSV1LWeFQIgrOGHQwB
ObpE85YCMQCNhS9zht0xv7j2FGuLshR3aLMTzY3UFBC3pEcI+yy4hI12MHh4laKT
yhW8MpHgDWs=
-----END CERTIFICATE-----`,
			ChainPEM: []string{
				`-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`,
			},
			WantErr: false,
		},
		"Bad leaf certificate format should error": {
			CertificatePEM: `-----BEGIN CERTIFICATE-----
BOO!
-----END CERTIFICATE-----`,
			ChainPEM: []string{
				`-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`,
			},
			WantErr: true,
		},
		"Bad chain certificate format should error": {
			CertificatePEM: `-----BEGIN CERTIFICATE-----
MIICFDCCAZmgAwIBAgIUAPsd9CUVr9TNG8nRzYHJrC/ZjtowCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MTExNjI4MjRaFw0yMjA1MTExNjM4MjNaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATGZIJr9odbCYVecVDp9LB1Ye9ehw7tCvPphaKQY832ftnRYFluAb6G
TtsmHqms4TXsTbvKHFJ9IxtvS6m2uJ6ao4HGMIHDMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTAROUd
EzzWfUH12GTQKrm84cGngTAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF
+jAjBgNVHREBAf8EGTAXgRVuYXRoYW5AY2hhaW5ndWFyZC5kZXYwKQYKKwYBBAGD
vzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMAoGCCqGSM49BAMDA2kA
MGYCMQDUnEwydrGWXaMdhE4JXvNAxAPI6iZzDFZAmqTsOyeSV1LWeFQIgrOGHQwB
ObpE85YCMQCNhS9zht0xv7j2FGuLshR3aLMTzY3UFBC3pEcI+yy4hI12MHh4laKT
yhW8MpHgDWs=
-----END CERTIFICATE-----`,
			ChainPEM: []string{
				`-----BEGIN CERTIFICATE-----
BOO!
-----END CERTIFICATE-----`,
			},
			WantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			csc, err := CreateCSCFromPEM(test.CertificatePEM, test.ChainPEM)
			if err != nil {
				if !test.WantErr {
					t.Error(err)
				}
				return
			}

			gotCert, err := csc.CertPEM()
			if err != nil {
				t.Error(err)
			}
			if diff := cmp.Diff(gotCert, test.CertificatePEM); diff != "" {
				t.Error(diff)
			}

			gotChain, err := csc.ChainPEM()
			if err != nil {
				t.Error(err)
			}
			if diff := cmp.Diff(gotChain, test.ChainPEM); diff != "" {
				t.Error(diff)
			}
		})
	}
}
