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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
)

type X509CA struct {
	RootCA  *x509.Certificate
	PrivKey crypto.Signer
}

func MakeX509(subject *challenges.ChallengeResult) (*x509.Certificate, error) {
	// TODO: Track / increment serial nums instead, although unlikely we will create dupes, it could happen
	uuid := uuid.New()
	var serialNumber big.Int
	serialNumber.SetBytes(uuid[:])

	cert := &x509.Certificate{
		SerialNumber: &serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * 10),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:     x509.KeyUsageCertSign,
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
	}
	cert.ExtraExtensions = append(IssuerExtension(subject.Issuer), AdditionalExtensions(subject)...)
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

	return ca.CreateCSCFromDER(subject, finalCertBytes, nil)
}

func AdditionalExtensions(subject *challenges.ChallengeResult) []pkix.Extension {
	res := []pkix.Extension{}
	if subject.TypeVal == challenges.GithubWorkflowValue {
		if trigger, ok := subject.AdditionalInfo[challenges.GithubWorkflowTrigger]; ok {
			res = append(res, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2},
				Value: []byte(trigger),
			})
		}

		if sha, ok := subject.AdditionalInfo[challenges.GithubWorkflowSha]; ok {
			res = append(res, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3},
				Value: []byte(sha),
			})
		}

		if name, ok := subject.AdditionalInfo[challenges.GithubWorkflowName]; ok {
			res = append(res, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4},
				Value: []byte(name),
			})
		}

		if repo, ok := subject.AdditionalInfo[challenges.GithubWorkflowRepository]; ok {
			res = append(res, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5},
				Value: []byte(repo),
			})
		}

		if ref, ok := subject.AdditionalInfo[challenges.GithubWorkflowRef]; ok {
			res = append(res, pkix.Extension{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6},
				Value: []byte(ref),
			})
		}
	}
	return res
}

func IssuerExtension(issuer string) []pkix.Extension {
	if issuer == "" {
		return nil
	}

	return []pkix.Extension{{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
		Value: []byte(issuer),
	}}
}
