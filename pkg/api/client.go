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
// limitations under the License.

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"
)

var (
	// DebugLog is used to log information that is useful for debugging.
	// Enable with: api.DebugLog.SetOutput(os.Stderr)
	DebugLog = log.New(ioutil.Discard, "", log.LstdFlags)
)

// Enabled checks to see if the logger's writer is set to something other
// than ioutil.Discard. This allows callers to avoid expensive operations
// that would end up in /dev/null.
func Enabled(l *log.Logger) bool {
	return l.Writer() != ioutil.Discard
}

type CertificateResponse struct {
	CertPEM  []byte
	ChainPEM []byte
	SCT      []byte
}

// SigstorePublicServerURL is the URL of Sigstore's public Fulcio service.
const SigstorePublicServerURL = "https://fulcio.sigstore.dev"

// Client is the interface for accessing the Fulcio API.
type Client interface {
	// SigningCert sends the provided CertificateRequest to the /api/v1/signingCert
	// endpoint of a Fulcio API, authenticated with the provided bearer token.
	SigningCert(cr CertificateRequest, token string) (*CertificateResponse, error)
}

// ClientOption is a functional option for customizing static signatures.
type ClientOption func(*clientOptions)

// NewClient creates a new Fulcio API client talking to the provided URL.
func NewClient(url *url.URL, opts ...ClientOption) Client {
	o := makeOptions(opts...)

	return &client{
		baseURL: url,
		client: &http.Client{
			Transport: createRoundTripper(http.DefaultTransport, o),
			Timeout:   o.Timeout,
		},
	}
}

type client struct {
	baseURL *url.URL
	client  *http.Client
}

var _ Client = (*client)(nil)

// SigningCert implements Client
func (c *client) SigningCert(cr CertificateRequest, token string) (*CertificateResponse, error) {
	// Construct the API endpoint for this handler
	endpoint := *c.baseURL
	endpoint.Path = path.Join(endpoint.Path, signingCertPath)

	b, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	// Set the authorization header to our OIDC bearer token.
	req.Header.Set("Authorization", "Bearer "+token)
	// Set the content-type to reflect we're sending JSON.
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// The API should return a 201 Created on success.  If we see anything else,
	// then turn the response body into an error.
	if resp.StatusCode != http.StatusCreated {
		return nil, errors.New(string(body))
	}

	// Extract the SCT from the response header.
	sct, err := base64.StdEncoding.DecodeString(resp.Header.Get("SCT"))
	if err != nil {
		return nil, err
	}

	// Split the cert and the chain
	certBlock, chainPem := pem.Decode(body)
	certPem := pem.EncodeToMemory(certBlock)
	return &CertificateResponse{
		CertPEM:  certPem,
		ChainPEM: chainPem,
		SCT:      sct,
	}, nil
}

type clientOptions struct {
	UserAgent string
	Timeout   time.Duration
}

func makeOptions(opts ...ClientOption) *clientOptions {
	o := &clientOptions{
		UserAgent: "",
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// WithTimeout sets the request timeout for the client
func WithTimeout(timeout time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.Timeout = timeout
	}
}

// WithUserAgent sets the media type of the signature.
func WithUserAgent(userAgent string) ClientOption {
	return func(o *clientOptions) {
		o.UserAgent = userAgent
	}
}

type roundTripper struct {
	http.RoundTripper
	UserAgent string
}

// RoundTrip implements `http.RoundTripper`
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", rt.UserAgent)

	// If no logging is needed, return early.
	if !Enabled(DebugLog) {
		return rt.RoundTripper.RoundTrip(req)
	}

	// From https://github.com/google/go-containerregistry/blob/main/pkg/v1/remote/transport/logger.go

	// Sanitize request URL, which is recommended by codeql.
	reqURL := strings.ReplaceAll(strings.ReplaceAll(req.URL.String(), "\n", ""), "\r", "")

	DebugLog.Printf("--> %s %s", req.Method, reqURL)
	// Save authorization header so that we can redact it.
	authToken := ""
	if req.Header != nil {
		authToken = req.Header.Get("authorization")
		if authToken != "" {
			req.Header.Set("authorization", "<redacted>")
		}
	}

	b, err := httputil.DumpRequestOut(req, false)
	if err == nil {
		DebugLog.Println(string(b))
	} else {
		DebugLog.Printf("Failed to dump request %s %s: %v", req.Method, reqURL, err)
	}

	// Restore the non-redacted authorization header.
	if req.Header != nil && authToken != "" {
		req.Header.Set("authorization", authToken)
	}

	start := time.Now()

	// Make request
	out, err := rt.RoundTripper.RoundTrip(req)

	duration := time.Since(start)
	if err != nil {
		DebugLog.Printf("<-- %v %s %s (%s)", err, req.Method, reqURL, duration)
	}
	if out != nil {
		msg := fmt.Sprintf("<-- %d", out.StatusCode)
		if out.Request != nil {
			msg = fmt.Sprintf("%s %s", msg, reqURL)
		}
		msg = fmt.Sprintf("%s (%s)", msg, duration)

		DebugLog.Print(msg)
		b, err := httputil.DumpResponse(out, false)
		if err == nil {
			DebugLog.Println(string(b))
		} else {
			DebugLog.Printf("Failed to dump response %s %s: %v", req.Method, reqURL, err)
		}
	}

	return out, err
}

func createRoundTripper(inner http.RoundTripper, o *clientOptions) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if o.UserAgent == "" {
		// There's nothing to do...
		return inner
	}
	return &roundTripper{
		RoundTripper: inner,
		UserAgent:    o.UserAgent,
	}
}
