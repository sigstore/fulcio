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
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/viper"
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

// IDTokenGetter is a type to get ID tokens for oauth flows
type IDTokenGetter struct {
	MessagePrinter func(url string)
	HTMLPage       string
}

type OIDCIDToken struct {
	RawString   string
	ParsedToken *oidc.IDToken
}

// DefaultIDTokenGetter is the default implementation.
// The HTML page and message printed to the terminal can be customized.
var DefaultIDTokenGetter = IDTokenGetter{
	MessagePrinter: func(url string) { fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", url) },
	HTMLPage:       htmlPage,
}

// GetIDToken is the default implementation
var GetIDToken = DefaultIDTokenGetter.getIDToken

func (i *IDTokenGetter) getIDToken(p *oidc.Provider, cfg oauth2.Config) (*OIDCIDToken, error) {
	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}

	// generate random fields
	stateToken, err := randStr()
	if err != nil {
		return nil, err
	}
	nonce, err := randStr()
	if err != nil {
		return nil, err
	}
	pkce, _ := NewPKCE(PKCES256)

	authCodeURL := cfg.AuthCodeURL(stateToken, append(pkce.AuthURLOpts(), oauth2.AccessTypeOnline, oidc.Nonce(nonce))...)
	fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", authCodeURL)
	if err := open.Run(authCodeURL); err != nil {
		return nil, err
	}

	code, err := getCodeFromLocalServer(stateToken, redirectURL)
	if err != nil {
		return nil, err
	}
	token, err := cfg.Exchange(context.Background(), code, append(pkce.TokenURLOpts(), oidc.Nonce(nonce))...)
	if err != nil {
		return nil, err
	}

	// requesting 'openid' scope should ensure an id_token is given when exchanging the code for an access token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token not present")
	}

	// verify nonce, client ID, access token hash before using it
	verifier := p.Verifier(&oidc.Config{ClientID: viper.GetString("oidc-client-id")})
	parsedIDToken, err := verifier.Verify(context.Background(), idToken)
	if err != nil {
		return nil, err
	}
	if parsedIDToken.Nonce != nonce {
		return nil, errors.New("nonce does not match value sent")
	}
	if parsedIDToken.AccessTokenHash != "" {
		if err := parsedIDToken.VerifyAccessToken(token.AccessToken); err != nil {
			return nil, err
		}
	}

	returnToken := OIDCIDToken{
		RawString:   idToken,
		ParsedToken: parsedIDToken,
	}
	return &returnToken, nil
}

func getCodeFromLocalServer(state string, redirectURL *url.URL) (string, error) {
	doneCh := make(chan string)
	errCh := make(chan error)
	m := http.NewServeMux()
	s := http.Server{
		Addr:    redirectURL.Host,
		Handler: m,
	}
	defer func() {
		_ = s.Shutdown(context.Background())
	}()

	go func() {
		m.HandleFunc(redirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
			// even though these are fetched from the FormValue method,
			// these are supplied as query parameters
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
	len := 32
	b := make([]byte, len)
	n, err := rand.Read(b)
	if err != nil {
		return "", err
	} else if n != len {
		return "", errors.New("short read")
	}

	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
