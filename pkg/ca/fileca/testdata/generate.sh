#!/bin/bash
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

password=password123
duration=36500 # 100 years

# ed25519
openssl req -x509 \
    -newkey ed25519 \
    -sha256 \
    -keyout ed25519-key.pem \
    -out ed25519-cert.pem \
    -subj "/CN=ed25519" \
    -days $duration \
    -addext basicConstraints=critical,CA:TRUE,pathlen:1 \
    -passout pass:"$password"

# ecdsa
openssl req -x509 \
    -newkey ec \
    -pkeyopt ec_paramgen_curve:secp384r1 \
    -sha256 \
    -keyout ecdsa-key.pem \
    -out ecdsa-cert.pem \
    -subj "/CN=ecdsa" \
    -days $duration \
    -addext basicConstraints=critical,CA:TRUE,pathlen:1 \
    -passout pass:"$password"

# RSA 4096
openssl req -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -keyout rsa4096-key.pem \
    -out rsa4096-cert.pem \
    -subj "/CN=rsa4096" \
    -days $duration \
    -addext basicConstraints=critical,CA:TRUE,pathlen:1 \
    -passout pass:"$password"

# mismatch cert (key doesn't match cert)
openssl req -x509 \
    -newkey ed25519 \
    -sha256 \
    -keyout mismatch-key.pem \
    -out mismatch-cert.pem \
    -subj "/CN=mismatch" \
    -days $duration \
    -addext basicConstraints=critical,CA:TRUE,pathlen:1 \
    -passout pass:"$password"

# Mess up the keys
cp ed25519-key.pem mismatch-key.pem

# Not a CA
openssl req -x509 \
    -newkey ed25519 \
    -sha256 \
    -keyout notca-key.pem \
    -out notca-cert.pem \
    -subj "/CN=notca" \
    -days $duration \
    -addext basicConstraints=critical,CA:FALSE,pathlen:1 \
    -passout pass:"$password"
