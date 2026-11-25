// Copyright 2026 The Sigstore Authors.
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

package ctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxJitter = 250 * time.Millisecond

// Logger is a simple logging interface used to log retry and backoff messages.
type Logger interface {
	Printf(string, ...any)
}

type basicLogger struct{}

func (*basicLogger) Printf(msg string, args ...any) {
	log.Printf(msg, args...)
}

// Options configures a CT log Client.
type Options struct {
	// Logger is used for retry and backoff messages; defaults to standard log package.
	Logger Logger
	// PublicKey is an optional PEM-encoded PKIX public key used to verify SCT signatures.
	PublicKey string
}

// RspError represents an error from the CT log server, including HTTP status and body.
type RspError struct {
	Err        error
	StatusCode int
	Body       []byte
}

func (e RspError) Error() string {
	return e.Err.Error()
}

func (e RspError) Unwrap() error {
	return e.Err
}

// Client submits certificates and precertificates to an RFC 6962 CT log.
type Client struct {
	uri        string
	httpClient *http.Client
	verifier   *SignatureVerifier
	logger     Logger
	backoff    *backoff
}

// NewClient constructs a new CT log Client.
func NewClient(uri string, hc *http.Client, opts Options) (*Client, error) {
	var verifier *SignatureVerifier
	if opts.PublicKey != "" {
		pubKey, err := ParsePublicKeyPEM([]byte(opts.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		verifier, err = NewSignatureVerifier(pubKey)
		if err != nil {
			return nil, err
		}
	}

	if hc == nil {
		hc = new(http.Client)
	}
	logger := opts.Logger
	if logger == nil {
		logger = &basicLogger{}
	}

	return &Client{
		uri:        strings.TrimRight(uri, "/"),
		httpClient: hc,
		verifier:   verifier,
		logger:     logger,
		backoff:    &backoff{},
	}, nil
}

// AddChain submits a DER-encoded certificate chain to /ct/v1/add-chain.
func (c *Client) AddChain(ctx context.Context, chain [][]byte) (*SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, X509LogEntryType, AddChainPath, chain)
}

// AddPreChain submits a DER-encoded precertificate chain to /ct/v1/add-pre-chain.
func (c *Client) AddPreChain(ctx context.Context, chain [][]byte) (*SignedCertificateTimestamp, error) {
	return c.addChainWithRetry(ctx, PrecertLogEntryType, AddPreChainPath, chain)
}

func (c *Client) addChainWithRetry(ctx context.Context, entryType LogEntryType, path string, chain [][]byte) (*SignedCertificateTimestamp, error) {
	req := AddChainRequest{Chain: chain}
	var resp AddChainResponse

	httpRsp, body, err := c.postAndParseWithRetry(ctx, path, &req, &resp)
	if err != nil {
		return nil, err
	}

	ds, err := UnmarshalDigitallySigned(resp.Signature)
	if err != nil {
		return nil, RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
	}

	exts, err := base64.StdEncoding.DecodeString(resp.Extensions)
	if err != nil {
		return nil, RspError{
			Err:        fmt.Errorf("invalid base64 data in Extensions (%q): %w", resp.Extensions, err),
			StatusCode: httpRsp.StatusCode,
			Body:       body,
		}
	}

	if len(resp.ID) != sha256.Size {
		return nil, RspError{
			Err:        fmt.Errorf("invalid log ID length: expected %d, got %d", sha256.Size, len(resp.ID)),
			StatusCode: httpRsp.StatusCode,
			Body:       body,
		}
	}

	var logID [sha256.Size]byte
	copy(logID[:], resp.ID)
	sct := &SignedCertificateTimestamp{
		SCTVersion: resp.SCTVersion,
		LogID:      logID,
		Timestamp:  resp.Timestamp,
		Extensions: exts,
		Signature:  ds,
	}

	if c.verifier != nil {
		if err := c.verifier.VerifySCTSignature(*sct, entryType, chain); err != nil {
			return nil, RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
		}
	}

	return sct, nil
}

func (c *Client) postAndParse(ctx context.Context, path string, req, rsp any) (*http.Response, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("context.Context required")
	}
	postBody, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	fullURI := c.uri + path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURI, bytes.NewReader(postBody))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpRsp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(httpRsp.Body)
	if err != nil {
		_ = httpRsp.Body.Close()
		return nil, nil, err
	}
	if err := httpRsp.Body.Close(); err != nil {
		return nil, nil, err
	}
	if httpRsp.Request != nil && httpRsp.Request.Method != http.MethodPost {
		return nil, nil, fmt.Errorf("POST request to %q was converted to %s request to %q", fullURI, httpRsp.Request.Method, httpRsp.Request.URL)
	}

	if httpRsp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, rsp); err != nil {
			return nil, nil, RspError{StatusCode: httpRsp.StatusCode, Body: body, Err: err}
		}
	}
	return httpRsp, body, nil
}

func (c *Client) waitForBackoff(ctx context.Context) error {
	/* #nosec G404 */ // Non-cryptographic jitter for HTTP retry backoff.
	jitter := time.Millisecond * time.Duration(rand.IntN(int(maxJitter.Milliseconds())))
	dur := max(time.Until(c.backoff.until().Add(jitter)), 0)
	timer := time.NewTimer(dur)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) postAndParseWithRetry(ctx context.Context, path string, req, rsp any) (*http.Response, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("context.Context required")
	}
	for {
		httpRsp, body, err := c.postAndParse(ctx, path, req, rsp)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, err
			}
			wait := c.backoff.set(nil)
			c.logger.Printf("Request to %s failed, backing-off %s: %s", c.uri, wait, err)
		} else {
			switch httpRsp.StatusCode {
			case http.StatusOK:
				return httpRsp, body, nil
			case http.StatusRequestTimeout:
				c.logger.Printf("Request to %s timed out, retrying immediately", c.uri)
			case http.StatusServiceUnavailable, http.StatusTooManyRequests:
				var override *time.Duration
				if retryAfter := httpRsp.Header.Get("Retry-After"); retryAfter != "" {
					if seconds, err := strconv.Atoi(retryAfter); err == nil {
						b := time.Duration(seconds) * time.Second
						override = &b
					} else if date, err := time.Parse(time.RFC1123, retryAfter); err == nil {
						b := time.Until(date)
						override = &b
					}
				}
				wait := c.backoff.set(override)
				c.logger.Printf("Request to %s failed, backing-off for %s: got HTTP status %s", c.uri, wait, httpRsp.Status)
			default:
				return nil, nil, RspError{
					StatusCode: httpRsp.StatusCode,
					Body:       body,
					Err:        fmt.Errorf("got HTTP status %q", httpRsp.Status),
				}
			}
		}
		if err := c.waitForBackoff(ctx); err != nil {
			return nil, nil, err
		}
	}
}
