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
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

const htmlPage = `<html>
<title>Sigstore Auth</title>
<body>
<h1>Sigstore Auth Successful</h1>
<p>You may now close this page.</p>
</body>
</html>
`

// AccessTokenGetter is a type to get access tokens for oauth flows
type AccessTokenGetter struct {
	MessagePrinter func(url string)
	HTMLPage       string
}

// DefaultAccessTokenGetter is the default implementation.
// The HTML page and message printed to the terminal can be customized.
var DefaultAccessTokenGetter = AccessTokenGetter{
	MessagePrinter: func(url string) { fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", url) },
	HTMLPage:       htmlPage,
}

// GetAccessToken is the default implementation
var GetAccessToken = DefaultAccessTokenGetter.getAccessToken

func (a *AccessTokenGetter) getAccessToken(p *oidc.Provider, cfg oauth2.Config) (string, error) {
	stateToken, err := randStr()
	if err != nil {
		return "", err
	}

	url := cfg.AuthCodeURL(stateToken, oauth2.AccessTypeOnline)
	fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", url)
	if err := open.Run(url); err != nil {
		return "", err
	}

	code, err := getCodeFromLocalServer(stateToken)
	if err != nil {
		return "", err
	}
	token, err := cfg.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func getCodeFromLocalServer(state string) (string, error) {
	doneCh := make(chan string)
	errCh := make(chan error)
	m := http.NewServeMux()
	s := http.Server{
		Addr:    "localhost:5556",
		Handler: m,
	}
	defer func() {
		_ = s.Shutdown(context.Background())
	}()

	go func() {
		m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.FormValue("state") != state {
				errCh <- errors.New("invalid state token")
				return
			}
			doneCh <- r.FormValue("code")
			fmt.Fprint(w, htmlPage)
		})
		if err := s.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	timeoutCh := time.NewTimer(120 * time.Second)
	select {
	case code := <-doneCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-timeoutCh.C:
		return "", errors.New("timeout")
	}
}

func randStr() (string, error) {
	buf := [10]byte{}
	n, err := rand.Read(buf[:])
	if err != nil {
		return "", err
	}
	if n != len(buf) {
		return "", errors.New("short read")
	}
	return base64.StdEncoding.EncodeToString(buf[:]), nil
}
