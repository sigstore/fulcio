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
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	logclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/pkg/errors"
)

type Client struct {
	c   *http.Client
	url string
}

func New(url string) *Client {
	c := &http.Client{Timeout: 30 * time.Second}
	return &Client{
		c:   c,
		url: url,
	}
}

type certChain struct {
	Chain []string `json:"chain"`
}

type certChainResponse struct {
	SctVersion int    `json:"sct_version"`
	ID         string `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

type ErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	ErrorCode  string `json:"errorCode"`
	Message    string `json:"message"`
}

func (err *ErrorResponse) Error() string {
	if err.ErrorCode == "" {
		return fmt.Sprintf("%d CT API error: %s", err.StatusCode, err.Message)
	}
	return fmt.Sprintf("%d (%s) CT API error: %s", err.StatusCode, err.ErrorCode, err.Message)
}

func (c *Client) AddPreChain(ctx context.Context, leaf string, chain []string) (*ct.SignedCertificateTimestamp, error) {
	tclient, err := logclient.New(c.url, c.c, jsonclient.Options{})
	if err != nil {
		return nil, errors.Wrap(err, "getting client")
	}

	// Build the PEM Chain {root, client}
	leafblock, _ := pem.Decode([]byte(leaf))
	var codeChain []ct.ASN1Cert
	codeChain = append(codeChain, ct.ASN1Cert{
		Data: leafblock.Bytes,
	})

	for _, c := range chain {
		decoded, _ := pem.Decode([]byte(c))
		codeChain = append(codeChain, ct.ASN1Cert{
			Data: []byte(decoded.Bytes),
		})
	}
	sct, err := tclient.AddPreChain(ctx, codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "adding pre chain")
	}
	return sct, nil
}

func (c *Client) AddChain(ctx context.Context, leaf string, chain []string) (*ct.SignedCertificateTimestamp, error) {
	tclient, err := logclient.New(c.url, c.c, jsonclient.Options{})
	if err != nil {
		return nil, errors.Wrap(err, "getting client")
	}

	// Build the PEM Chain {root, client}
	leafblock, _ := pem.Decode([]byte(leaf))
	var codeChain []ct.ASN1Cert
	codeChain = append(codeChain, ct.ASN1Cert{
		Data: leafblock.Bytes,
	})

	for _, c := range chain {
		decoded, _ := pem.Decode([]byte(c))
		codeChain = append(codeChain, ct.ASN1Cert{
			Data: []byte(decoded.Bytes),
		})
	}
	sct, err := tclient.AddChain(ctx, codeChain)
	if err != nil {
		return nil, errors.Wrap(err, "adding pre chain")
	}
	return sct, nil
}
