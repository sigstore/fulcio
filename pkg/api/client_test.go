//
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

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUserAgentOption(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "foo" {
			t.Error(`expected user-agent to be set to "foo"`)
		}
	}))

	lc := NewClient(nil, WithUserAgent("foo"))
	c, ok := lc.(*client)
	if !ok {
		t.Fatal("wrong legacy client implementation")
	}

	_, err := c.client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutOption(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))

	lc := NewClient(nil, WithTimeout(time.Second))
	c, ok := lc.(*client)
	if !ok {
		t.Fatal("wrong legacy client implementation")
	}

	_, err := c.client.Get(ts.URL)
	if err == nil {
		t.Error("expected client to get timeout error on request")
	}
	if strings.HasPrefix(err.Error(), "context deadline exceeded") {
		t.Error("expected client to specifically have a timeout error")
	}
}

func TestRetryCountOption(t *testing.T) {
	currentCount := 0
	expectedCount := 2
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			currentCount++
			file := []byte{}

			if currentCount < expectedCount {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(file)
			}

		}))

	lc := NewClient(nil, WithRetryCount(2))
	c, ok := lc.(*client)
	if !ok {
		t.Fatal("wrong legacy client implementation")
	}

	_, err := c.client.Get(ts.URL)
	if err != nil {
		t.Error("expected client to retry requestt")
	}
}
