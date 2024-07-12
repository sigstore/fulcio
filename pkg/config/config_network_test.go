// Copyright 2022 The Sigstore Authors.
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

//go:build !hermetic

package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/fulcio/pkg/certificate"
)

func TestLoadYamlConfig(t *testing.T) {
	td := t.TempDir()
	cfgPath := filepath.Join(td, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(validYamlCfg), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cfg.GetIssuer("https://accounts.google.com")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "foo" {
		t.Errorf("expected foo, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://accounts.google.com" {
		t.Errorf("expected https://accounts.google.com, got %s", got.IssuerURL)
	}
	if got := len(cfg.OIDCIssuers); got != 1 {
		t.Errorf("expected 1 issuer, got %d", got)
	}

	got, ok = cfg.GetIssuer("https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "bar" {
		t.Errorf("expected bar, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER" {
		t.Errorf("expected https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER, got %s", got.IssuerURL)
	}

	if _, ok := cfg.GetIssuer("not_an_issuer"); ok {
		t.Error("no error returned from an unconfigured issuer")
	}
}

func TestLoadJsonConfig(t *testing.T) {
	td := t.TempDir()
	cfgPath := filepath.Join(td, "config.json")
	if err := os.WriteFile(cfgPath, []byte(validJSONCfg), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cfg.GetIssuer("https://accounts.google.com")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "foo" {
		t.Errorf("expected foo, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://accounts.google.com" {
		t.Errorf("expected https://accounts.google.com, got %s", got.IssuerURL)
	}
	if got := len(cfg.OIDCIssuers); got != 1 {
		t.Errorf("expected 1 issuer, got %d", got)
	}

	got, ok = cfg.GetIssuer("https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER")
	if !ok {
		t.Error("expected true, got false")
	}
	if got.ClientID != "bar" {
		t.Errorf("expected bar, got %s", got.ClientID)
	}
	if got.IssuerURL != "https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER" {
		t.Errorf("expected https://oidc.eks.fantasy-land.amazonaws.com/id/CLUSTERIDENTIFIER, got %s", got.IssuerURL)
	}

	if _, ok := cfg.GetIssuer("not_an_issuer"); ok {
		t.Error("no error returned from an unconfigured issuer")
	}
}

func TestParseTemplate(t *testing.T) {

	validTemplate := "{{.foobar}}"
	invalidTemplate := "{{.foobar}"
	ciissuerMetadata := make(map[string]IssuerMetadata)
	ciissuerMetadata["github"] = IssuerMetadata{
		ExtensionTemplates: certificate.Extensions{
			BuildTrigger: invalidTemplate,
		},
	}
	fulcioConfig := &FulcioConfig{
		CIIssuerMetadata: ciissuerMetadata,
	}
	// BuildTrigger as a invalid template should raise an error
	err := validateCIIssuerMetadata(fulcioConfig)
	if err == nil {
		t.Error("invalid template should raise an error")
	}
	ciissuerMetadata["github"] = IssuerMetadata{
		ExtensionTemplates: certificate.Extensions{
			BuildTrigger: validTemplate,
		},
	}
	fulcioConfig = &FulcioConfig{
		CIIssuerMetadata: ciissuerMetadata,
	}
	// BuildTrigger as a valid template shouldn't raise an error
	err = validateCIIssuerMetadata(fulcioConfig)
	if err != nil {
		t.Error("valid template shouldn't raise an error, error: %w", err)
	}
	ciissuerMetadata["github"] = IssuerMetadata{
		SubjectAlternativeNameTemplate: invalidTemplate,
	}
	fulcioConfig = &FulcioConfig{
		CIIssuerMetadata: ciissuerMetadata,
	}
	// A SAN as a invalid template should raise an error
	err = validateCIIssuerMetadata(fulcioConfig)
	if err == nil {
		t.Error("invalid SAN should raise an error")
	}
	ciissuerMetadata["github"] = IssuerMetadata{
		SubjectAlternativeNameTemplate: invalidTemplate,
	}
	fulcioConfig = &FulcioConfig{
		CIIssuerMetadata: ciissuerMetadata,
	}
	// A SAN as a valid template should raise an error
	err = validateCIIssuerMetadata(fulcioConfig)
	if err == nil {
		t.Error("valid SAN shouldn't raise an error")
	}
}

func TestLoadDefaults(t *testing.T) {
	td := t.TempDir()

	// Don't put anything here!
	cfgPath := filepath.Join(td, "config.yaml")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(DefaultConfig, cfg, cmpopts.IgnoreUnexported(FulcioConfig{})); diff != "" {
		t.Errorf("DefaultConfig(): -want +got: %s", diff)
	}

	ctx := context.Background()

	if got := FromContext(ctx); nil != got {
		t.Errorf("FromContext(): %#v, wanted nil", got)
	}

	ctx = With(ctx, cfg)
	if diff := cmp.Diff(cfg, FromContext(ctx), cmpopts.IgnoreUnexported(FulcioConfig{})); diff != "" {
		t.Errorf("FromContext(): -want +got: %s", diff)
	}
}
