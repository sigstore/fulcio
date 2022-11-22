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

package v1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/durationpb"
)

type CertAuthorityService struct {
	certAuthority       string
	certAuthorityParent string
	caPoolParent        string
	client              *privateca.CertificateAuthorityClient

	// protected by once
	cachedRoots     [][]*x509.Certificate
	cachedRootsOnce sync.Once
}

func NewCertAuthorityService(ctx context.Context, parent string, opts ...option.ClientOption) (ca.CertificateAuthority, error) {
	client, err := privateca.NewCertificateAuthorityClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	c := CertAuthorityService{
		client: client,
	}

	if !strings.Contains(parent, "certificateAuthorities") {
		c.caPoolParent = parent
		return &c, nil
	}
	// parent should be in the form projects/*/locations/*/caPools/*/certificateAuthorities/*
	// to create a cert, we only want projects/*/locations/*/caPools/*
	caPoolParent := strings.Split(parent, "/certificateAuthorities")
	c.caPoolParent = caPoolParent[0]

	s := strings.SplitAfter(parent, "certificateAuthorities/")
	if len(s) != 2 {
		return nil, fmt.Errorf("certificate authority should be specified in the format projects/*/locations/*/caPools/*/certificateAuthorities/*")
	}
	c.certAuthority = s[1]
	c.certAuthorityParent = parent
	return &c, nil
}

// getPubKeyFormat Returns the PublicKey KeyFormat required by gcp privateca.
// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1#PublicKey_KeyType
func getPubKeyFormat(pemBytes []byte) (privatecapb.PublicKey_KeyFormat, error) {
	block, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse public key: " + err.Error())
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return privatecapb.PublicKey_PEM, nil
	default:
		return 0, fmt.Errorf("unknown public key type: %v", pub)
	}
}

func convertID(id asn1.ObjectIdentifier) []int32 {
	nid := make([]int32, 0, len(id))
	for _, digit := range id {
		nid = append(nid, int32(digit))
	}
	return nid
}

func Req(parent, certAuthority string, pemBytes []byte, cert *x509.Certificate) (*privatecapb.CreateCertificateRequest, error) {
	pubkeyFormat, err := getPubKeyFormat(pemBytes)
	if err != nil {
		return nil, err
	}

	// Translate the x509 certificate's subject to Google proto.
	subject := &privatecapb.CertificateConfig_SubjectConfig{
		Subject: &privatecapb.Subject{},
		SubjectAltName: &privatecapb.SubjectAltNames{
			EmailAddresses: cert.EmailAddresses,
		},
	}
	for _, uri := range cert.URIs {
		subject.SubjectAltName.Uris = append(subject.SubjectAltName.Uris, uri.String())
	}

	extensions := make([]*privatecapb.X509Extension, 0, len(cert.ExtraExtensions))
	for _, ext := range cert.ExtraExtensions {
		extensions = append(extensions, &privatecapb.X509Extension{
			ObjectId: &privatecapb.ObjectId{
				ObjectIdPath: convertID(ext.Id),
			},
			Value: ext.Value,
		})
	}

	req := &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(time.Until(cert.NotAfter)),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: pubkeyFormat,
						Key:    pemBytes,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								CodeSigning: true,
							},
						},
						AdditionalExtensions: extensions,
					},
					SubjectConfig: subject,
				},
			},
		},
	}

	if certAuthority != "" {
		req.IssuingCertificateAuthorityId = certAuthority
	}

	return req, nil
}

func (c *CertAuthorityService) TrustBundle(ctx context.Context) ([][]*x509.Certificate, error) {
	// if we've already successfully fetched the CA info, just use the cached value
	if c.cachedRoots != nil {
		return c.cachedRoots, nil
	}

	// if a specific certificate authority was specified, use that one
	if c.certAuthorityParent != "" {
		return c.getCertificateAuthorityTrustBundle(ctx)
	}
	// otherwise, get certs from all of the CAs in the pool
	return c.listCertificateAuthorityTrustBundle(ctx)
}

func (c *CertAuthorityService) getCertificateAuthorityTrustBundle(ctx context.Context) ([][]*x509.Certificate, error) {
	var roots [][]*x509.Certificate
	ca, err := c.client.GetCertificateAuthority(ctx, &privatecapb.GetCertificateAuthorityRequest{
		Name: c.certAuthorityParent,
	})
	if err != nil {
		return nil, err
	}
	// if we fail to parse the PEM content, return an error
	caCerts, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(strings.Join(ca.PemCaCertificates, "")))
	if err != nil {
		return [][]*x509.Certificate{}, fmt.Errorf("failed parsing PemCACertificates response: %w", err)
	}
	if len(caCerts) == 0 {
		return [][]*x509.Certificate{}, fmt.Errorf("error fetching root certificates")
	}
	roots = append(roots, caCerts)

	c.cachedRootsOnce.Do(func() {
		c.cachedRoots = roots
	})

	return c.cachedRoots, nil
}

func (c *CertAuthorityService) listCertificateAuthorityTrustBundle(ctx context.Context) ([][]*x509.Certificate, error) {
	// fetch the latest values for the specified CA pool
	var roots [][]*x509.Certificate
	cas := c.client.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
		Parent: c.caPoolParent,
	})
	for {
		ca, done := cas.Next()
		if done == iterator.Done {
			break
		} else if done != nil {
			// if the iterator returns an issue for some reason, exit
			return [][]*x509.Certificate{}, done
		}
		// if we fail to parse the PEM content, return an error
		caCerts, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(strings.Join(ca.PemCaCertificates, "")))
		if err != nil {
			return [][]*x509.Certificate{}, fmt.Errorf("failed parsing PemCACertificates response: %w", err)
		}
		if len(caCerts) == 0 {
			return [][]*x509.Certificate{}, fmt.Errorf("error fetching root certificates")
		}
		roots = append(roots, caCerts)
	}
	c.cachedRootsOnce.Do(func() {
		c.cachedRoots = roots
	})

	return c.cachedRoots, nil
}

func (c *CertAuthorityService) CreateCertificate(ctx context.Context, principal identity.Principal, publicKey crypto.PublicKey) (*ca.CodeSigningCertificate, error) {
	cert, err := ca.MakeX509(ctx, principal, publicKey)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	req, err := Req(c.caPoolParent, c.certAuthority, pubKeyBytes, cert)
	if err != nil {
		return nil, ca.ValidationError(err)
	}

	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	return ca.CreateCSCFromPEM(resp.PemCertificate, resp.PemCertificateChain)
}
