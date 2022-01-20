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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithMaxBytes(t *testing.T) {
	var maxBodySize int64 = 10
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	ts := httptest.NewServer(WithMaxBytes(handler, maxBodySize))

	tests := map[string]struct {
		Body           string
		ExpectedStatus int
	}{
		"Less than max": {
			Body:           strings.Repeat("a", int(maxBodySize-1)),
			ExpectedStatus: http.StatusOK,
		},
		"At max": {
			Body:           strings.Repeat("b", int(maxBodySize)),
			ExpectedStatus: http.StatusOK,
		},
		"Over max": {
			Body:           strings.Repeat("c", int(maxBodySize+1)),
			ExpectedStatus: http.StatusBadRequest,
		},
	}

	for testcase, data := range tests {
		t.Run(testcase, func(t *testing.T) {
			resp, err := http.Post(ts.URL, "text/plain", strings.NewReader(data.Body))
			if err != nil {
				t.Fatal("Failed to send request to test server", err)
			}
			if resp.StatusCode != data.ExpectedStatus {
				t.Error("Expected status code", data.ExpectedStatus, "but got", resp.StatusCode)
			}
		})
	}
}
