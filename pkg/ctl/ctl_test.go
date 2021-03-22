/*
Copyright © 2021 Luke Hinds <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ctl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/stretchr/testify/assert"
)

var root_cert = "-----BEGIN CERTIFICATE-----\nMIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo\nMQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw\ncGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI\ndGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD\nVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt\nMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl\ncnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY\nYEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw\nZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU\nT8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi\nHOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc\nOljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==\n-----END CERTIFICATE-----"
var client_cert = []string{"-----BEGIN CERTIFICATE-----\nMIIC5jCCAoygAwIBAgIUALS5S4DcAcEkpFLn2QzXvbwiQOQwCgYIKoZIzj0EAwIw\naDELMAkGA1UEBhMCVUsxEjAQBgNVBAgTCVdpbHRzaGlyZTETMBEGA1UEBxMKQ2hp\ncHBlbmhhbTEPMA0GA1UEChMGUmVkSGF0MQwwCgYDVQQLEwNDVE8xETAPBgNVBAMT\nCHRlc3RjZXJ0MB4XDTIxMDMxNDE3MTMwNVoXDTIxMDMxNDE3MzMwNVowODEaMBgG\nA1UECgwRbGhpbmRzQHJlZGhhdC5jb20xGjAYBgNVBAMMEWxoaW5kc0ByZWRoYXQu\nY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEulSDY501IgUOr6OPd6s+IBpMTwVq\n4Qy1nfxbPDumw2T4CczsA/jl0wW2SQqcupgYjQ/3rjDPRNnVrGHUPtGItlZSZufs\nBVkFlvUGkMqHciAeQVrZJ7xMQsuDScxddO4Go4IBJTCCASEwDgYDVR0PAQH/BAQD\nAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE\nFJax5VyYhhNouC0fZDQLd9H1eqGLMB8GA1UdIwQYMBaAFE/CcJuiblW9HbIrh1ET\nohzjlR1ZMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRwOi8vcHJp\ndmF0ZWNhLWNvbnRlbnQtNjA0Njk2OGEtMDAwMC0yNjljLWI1ZTYtM2MyODZkM2Jm\nMjNhLnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vMDVhYjQxYmU5Mjk3MzI0YmU2N2Yv\nY2EuY3J0MBwGA1UdEQQVMBOBEWxoaW5kc0ByZWRoYXQuY29tMAoGCCqGSM49BAMC\nA0gAMEUCIQD5L6P1V8rkvRH2WtXY6hSSx0/ZfoaGw1a+8adDQHNVSgIgP6Bi+fLM\nqtXZTMf6+1z82QcsbjHKqUWzkxRz+0yraZI=\n-----END CERTIFICATE-----"}

func Test_AddChain(t *testing.T) {
	logID := [32]byte{
		'c', 't', 'l', 'o', 'g', '_', 'i', 'd', '_', 'f', 'o', 'r', '_', 't', 'e', 's',
		't', 'i', 'n', 'g', '_', 'p', 'u', 'r', 'p', 'o', 's', 'e', 's', '!', '!', '1',
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"SCTVersion":0,"LogID":{"KeyID":[99,116,108,111,103,95,105,100,95,102,111,114,95,116,101,115,116,105,110,103,95,112,117,114,112,111,115,101,115,33,33,49]},"Timestamp":1615659852192,"Extensions":"ZXh0","Signature":"AAAAA3NpZw=="}
		`))
		if err != nil {
			fmt.Println(err)
		}
	}))
	defer server.Close()

	api := Client{server.Client(), server.URL}
	body, err := api.Add(root_cert, client_cert, ct.AddChainPath)
	if err != nil {
		t.Fatalf("error adding chain: %v", err)
	}
	assert.Equal(t, body.SCTVersion.String(), ct.V1.String())
	assert.Equal(t, body.LogID.KeyID[:], logID[:])
	assert.Equal(t, body.Timestamp, uint64(1615659852192))
	assert.Equal(t, string(body.Extensions), "ext")
	assert.Equal(t, string(body.Signature.Signature), "sig")

}
