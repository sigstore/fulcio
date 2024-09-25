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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/fulcio/pkg/ca/tinkca"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

/*
To run:
go run cmd/create_tink_keyset/create_tink_keyset.go \
  --kms-resource="gcp-kms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>" \
  --output="enc-keyset.cfg"

You can also create a GCP KMS encrypted Tink keyset with tinkey:
tinkey create-keyset --key-template ECDSA_P384 --out enc-keyset.cfg --master-key-uri gcp-kms://projects/<project>/locations/<region>/keyRings/<key-ring>/cryptoKeys/<key>

You must have the permissions to read the KMS key, and create a certificate in the CA pool.
*/

var (
	kmsKey     = flag.String("kms-resource", "", "Resource path to KMS key, starting with gcp-kms:// or aws-kms://")
	outputPath = flag.String("output", "", "Path to the output file")
)

func main() {
	flag.Parse()
	if *kmsKey == "" {
		log.Fatal("kms-resource must be set")
	}
	if *outputPath == "" {
		log.Fatal("output must be set")
	}

	kh, err := keyset.NewHandle(signature.ECDSAP384KeyWithoutPrefixTemplate())
	if err != nil {
		log.Fatal(err)
	}

	primaryKey, err := tinkca.GetPrimaryKey(context.Background(), *kmsKey)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(*outputPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	jsonWriter := keyset.NewJSONWriter(f)
	if err := kh.Write(jsonWriter, primaryKey); err != nil {
		fmt.Printf("error writing primary key: %v\n", err)
	}
}
