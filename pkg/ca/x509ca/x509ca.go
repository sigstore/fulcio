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
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/challenges"
	"github.com/sigstore/fulcio/pkg/pkcs11"
	"github.com/spf13/viper"
)

type X509CA struct {
	RootCA  *x509.Certificate
	PrivKey crypto.Signer
}

func NewX509CA() (*X509CA, error) {
	ca := &X509CA{}
	p11Ctx, err := pkcs11.InitHSMCtx()
	if err != nil {
		return nil, err
	}
	defer p11Ctx.Close()

	rootID := []byte(viper.GetString("hsm-caroot-id"))

	// get the existing root CA from the HSM or from disk
	if !viper.IsSet("aws-hsm-root-ca-path") {
		ca.RootCA, err = p11Ctx.FindCertificate(rootID, nil, nil)
		if err != nil {
			return nil, err
		}
	} else {
		rootCaPath := filepath.Clean(viper.GetString("aws-hsm-root-ca-path"))
		pubPEMData, err := os.ReadFile(rootCaPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pubPEMData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("failed to decode PEM block containing certificate")
		}
		ca.RootCA, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	// get the private key object from HSM
	ca.PrivKey, err = p11Ctx.FindKeyPair(nil, []byte("PKCS11CA"))
	if err != nil {
		return nil, err
	}

	return ca, nil

}

func (x *X509CA) CreateCertificate(_ context.Context, subject *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
	return x.CreateCertificateWithCA(x, subject)
}

func (x *X509CA) CreateCertificateWithCA(certauth *X509CA, subject *challenges.ChallengeResult) (*ca.CodeSigningCertificate, error) {
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
	cert.ExtraExtensions = append(IssuerExtension(subject.Issuer), GithubWorkflowExtension(subject.WorkflowInfo)...)

	finalCertBytes, err := x509.CreateCertificate(rand.Reader, cert, certauth.RootCA, subject.PublicKey, certauth.PrivKey)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromDER(subject, finalCertBytes, nil)
}

func GithubWorkflowExtension(info challenges.WorkflowResult) []pkix.Extension {
	res := []pkix.Extension{}
	if info.Sha != "" {
		res = append(res, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2},
			Value: []byte(info.Sha),
		})
	}

	if info.Trigger != "" {
		res = append(res, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3},
			Value: []byte(info.Trigger),
		})
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
