/*
Copyright © 2021 Dan Lorenc <lorenc.d@gmail.com>

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

package oauthflow

import (
	"net/http"
	"net/url"
	"testing"
)

func TestGetCodeWorking(t *testing.T) {
	desiredState := "foo"
	desiredCode := "code"
	// We need to start this in the background and send our request to the server

	var gotCode string
	var gotErr error
	doneCh := make(chan int)
	go func() {
		gotCode, gotErr = getCodeFromLocalServer(desiredState)
		doneCh <- 1
	}()

	sendCodeAndState(t, desiredCode, desiredState)
	<-doneCh

	if gotErr != nil {
		t.Fatal(gotErr)
	}
	if gotCode != desiredCode {
		t.Errorf("got %s, expected %s", gotCode, desiredCode)
	}
}

func TestGetCodeWrongState(t *testing.T) {
	desiredState := "foo"
	desiredCode := "code"
	// We need to start this in the background and send our request to the server

	var gotErr error
	doneCh := make(chan int)
	go func() {
		_, gotErr = getCodeFromLocalServer(desiredState)
		doneCh <- 1
	}()

	sendCodeAndState(t, desiredCode, "WRONG")
	<-doneCh

	if gotErr == nil {
		t.Fatal("expected error, sent wrong state!")
	}
}

func sendCodeAndState(t *testing.T, code, state string) {
	values := url.Values{}
	values.Set("code", code)
	values.Set("state", state)
	if _, err := http.PostForm("http://localhost:5556", values); err != nil {
		t.Fatal(err)
	}
}
