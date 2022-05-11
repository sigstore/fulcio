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

package x509ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type X509CA struct {
	RootCA  *x509.Certificate
	PrivKey crypto.Signer
}

func MakeX509(subject *challenges.ChallengeResult) (*x509.Certificate, error) {
	serialNumber, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	skid, err := cryptoutils.SKID(subject.PublicKey)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * 10),
		SubjectKeyId: skid,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	switch subject.TypeVal {
	case challenges.EmailValue:
		cert.EmailAddresses = []string{subject.Value}
	case challenges.SpiffeValue:
		challengeURL, err := url.Parse(subject.Value)
		if err != nil {
			return nil, ca.ValidationError(err)
		}
		cert.URIs = []*url.URL{challengeURL}
	case challenges.GithubWorkflowValue:
		jobWorkflowURI, err := url.Parse(subject.Value)
		if err != nil {
			return nil, ca.ValidationError(err)
		}
		cert.URIs = []*url.URL{jobWorkflowURI}
	case challenges.KubernetesValue:
		k8sURI, err := url.Parse(subject.Value)
		if err != nil {
			return nil, ca.ValidationError(err)
		}
		cert.URIs = []*url.URL{k8sURI}
	case challenges.URIValue:
		subjectURI, err := url.Parse(subject.Value)
		if err != nil {
			return nil, ca.ValidationError(err)
		}
		cert.URIs = []*url.URL{subjectURI}
	case challenges.UsernameValue:
		cert.EmailAddresses = []string{subject.Value}
	}

	exts := Extensions{
		Issuer: subject.Issuer,
	}
	if subject.TypeVal == challenges.GithubWorkflowValue {
		var ok bool
		exts.GithubWorkflowTrigger, ok = subject.AdditionalInfo[challenges.GithubWorkflowTrigger]
		if !ok {
			return nil, errors.New("x509ca: github workflow missing trigger claim")
		}
		exts.GithubWorkflowSHA, ok = subject.AdditionalInfo[challenges.GithubWorkflowSha]
		if !ok {
			return nil, errors.New("x509ca: github workflow missing SHA claim")
		}
		exts.GithubWorkflowName, ok = subject.AdditionalInfo[challenges.GithubWorkflowName]
		if !ok {
			return nil, errors.New("x509ca: github workflow missing workflow name claim")
		}
		exts.GithubWorkflowRepository, ok = subject.AdditionalInfo[challenges.GithubWorkflowRepository]
		if !ok {
			return nil, errors.New("x509ca: github workflow missing repository claim")
		}
		exts.GithubWorkflowRef, ok = subject.AdditionalInfo[challenges.GithubWorkflowRef]
		if !ok {
			return nil, errors.New("x509ca: github workflow missing ref claim")
		}
	}

	cert.ExtraExtensions, err = exts.Render()
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (x *X509CA) Root(ctx context.Context) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x.RootCA.Raw,
	}), nil
}

func (x *X509CA) CreateCertificate(_ context.Context, subject *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	cert, err := MakeX509(subject)
	if err != nil {
		return nil, err
	}

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, x.RootCA, subject.PublicKey, x.PrivKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(finalCertBytes, []*x509.Certificate{x.RootCA})
}
