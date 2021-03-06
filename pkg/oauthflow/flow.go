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

func GetAccessToken(p *oidc.Provider, cfg oauth2.Config) (string, error) {
	stateToken, err := randStr()
	if err != nil {
		return "", err
	}

	codeCh, errCh := startServer(stateToken)

	url := cfg.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	fmt.Fprintf(os.Stderr, "Your browser will now be opened to:\n%s\n", url)
	if err := open.Run(url); err != nil {
		return "", err
	}

	timeoutCh := time.NewTimer(120 * time.Second)
	select {
	case code := <-codeCh:
		token, err := cfg.Exchange(context.Background(), code)
		if err != nil {
			return "", err
		}
		return token.AccessToken, nil
	case err := <-errCh:
		return "", err
	case <-timeoutCh.C:
		return "", errors.New("timeout")
	}
}

const htmlPage = `<html>
<title>Sigstore Auth</title>
<body>
<h1>Sigstore Auth Successful</h1>
<p>You may now close this page.</p>
</body>
</html>
`

func startServer(state string) (chan string, chan error) {
	doneCh := make(chan string)
	errCh := make(chan error)
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.FormValue("state") != state {
				errCh <- errors.New("invalid state token")
				return
			}
			doneCh <- r.FormValue("code")
			fmt.Fprint(w, htmlPage)
		})
		if err := http.ListenAndServe("localhost:5556", nil); err != nil {
			errCh <- err
		}
	}()
	return doneCh, errCh
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
