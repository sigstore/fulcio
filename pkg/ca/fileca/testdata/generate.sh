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
duration=876000h # 100 years
tpl=temp.tpl

function generate_ed25519 {
    echo $password > password.file 

    step certificate create \
        --profile root-ca \
        --not-after $duration \
        --kty OKP \
        --crv Ed25519 \
        --password-file password.file \
        ed25519 \
        ed25519-cert.pem \
        ed25519-key.pem

    rm password.file
}

function generate_ecdsa {
    echo $password > password.file
    
    step certificate create \
        --profile root-ca \
        --not-after $duration \
        --kty EC \
        --crv P-384 \
        --password-file password.file \
        ecdsa \
        ecdsa-cert.pem \
        ecdsa-key.pem
    
    rm password.file
}

function generate_rsa4096 {
    echo $password > password.file

    step certificate create \
        --profile root-ca \
        --not-after $duration \
        --kty RSA \
        --size 4096 \
        --password-file password.file \
        rsa4096 \
        rsa4096-cert.pem \
        rsa4096-key.pem

    rm password.file
}

function generate_openssl {
    # OpenSSL uses a different encryption format
    # than step so lets makes sure that works
    openssl req -x509 \
        -newkey ed25519 \
        -sha256 \
        -keyout openssl-key.pem \
        -out openssl-cert.pem \
        -subj "/CN=openssl" \
        -days 36500 \
        -addext basicConstraints=critical,CA:TRUE,pathlen:1 \
        -passout pass:"$password"
} 

function generate_key_mismatch {
    echo $password > password.file 
    step certificate create \
        --profile root-ca \
        --not-after $duration \
        --kty OKP \
        --crv Ed25519 \
        --password-file password.file \
        mismatch \
        temp-cert.pem \
        temp-key.pem

    step certificate create \
        --profile root-ca \
        --not-after $duration \
        --kty OKP \
        --crv Ed25519 \
        --password-file password.file \
        mismatch \
        mismatch-cert.pem \
        mismatch-key.pem

    mv temp-key.pem mismatch-key.pem
    rm temp-cert.pem
    rm password.file
}
    
function generate_not_a_ca {
    echo $password > password.file

    step certificate create \
        --ca ed25519-cert.pem \
        --ca-key ed25519-key.pem \
        --ca-password-file password.file \
        --profile leaf \
        --not-after $duration \
        --kty OKP \
        --crv Ed25519 \
        --password-file password.file \
        notca \
        notca-cert.pem \
        notca-key.pem

    rm password.file
}

function generate_intermediate_2_ca {
    echo $password > password.file
    
    # Root CA
    cat <<-EOF > root.tpl
    {
        "subject": {
            "commonName": "root"
        },
        "issuer": {
            "commonName": "root"
        },
        "keyUsage": ["certSign", "crlSign"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 1
        }
    }
EOF

    step certificate create \
        --template root.tpl \
        --password-file password.file \
        --not-after $duration \
        root \
        root-cert.pem \
        root-key.pem \
    
    rm root.tpl

    # Intermediate 1
    cat <<-EOF > intermediate1.tpl
    {
        "subject": {
            "commonName": "intermediate1"
        },
        "keyUsage": ["certSign", "crlSign"],
        "extKeyUsage": ["codeSigning"],
        "basicConstraints": {
            "isCA": true
        }
    }
EOF
    
    step certificate create \
        --template intermediate1.tpl \
        --password-file password.file \
        --not-after $duration \
        --kty OKP \
        --curve Ed25519 \
        --ca root-cert.pem \
        --ca-key root-key.pem \
        --ca-password-file password.file \
        intermediate1 \
        intermediate1-cert.pem \
        intermediate1-key.pem \
   
    rm root-key.pem 
    rm intermediate1.tpl

    # Chain certificates together and delete unneeded ones
    cat intermediate1-cert.pem root-cert.pem > intermediate-2-cert.pem
    mv intermediate1-key.pem intermediate-2-key.pem
    rm intermediate1-cert.pem root-cert.pem 

    rm password.file
}

function generate_intermediate_3_ca {
    echo $password > password.file
    
    # Root CA
    cat <<-EOF > root.tpl
    {
        "subject": {
            "commonName": "root"
        },
        "issuer": {
            "commonName": "root"
        },
        "keyUsage": ["certSign", "crlSign"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 2
        }
    }
EOF

    step certificate create \
        --template root.tpl \
        --password-file password.file \
        --not-after $duration \
        root \
        root-cert.pem \
        root-key.pem \
    
    rm root.tpl

    # Intermediate 1
    cat <<-EOF > intermediate1.tpl
    {
        "subject": {
            "commonName": "intermediate1"
        },
        "keyUsage": ["certSign", "crlSign"],
        "extKeyUsage": ["codeSigning"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 1
        }
    }
EOF
    
    step certificate create \
        --template intermediate1.tpl \
        --password-file password.file \
        --not-after $duration \
        --kty OKP \
        --curve Ed25519 \
        --ca root-cert.pem \
        --ca-key root-key.pem \
        --ca-password-file password.file \
        intermediate1 \
        intermediate1-cert.pem \
        intermediate1-key.pem \
   
    rm root-key.pem 
    rm intermediate1.tpl

    # Intermediate 2
    cat <<-EOF > intermediate2.tpl
    {
        "subject": {
            "commonName": "intermediate2"
        },
        "keyUsage": ["certSign", "crlSign"],
        "extKeyUsage": ["codeSigning"],
        "basicConstraints": {
            "isCA": true
        }
    }
EOF
    
    step certificate create \
        --template intermediate2.tpl \
        --password-file password.file \
        --not-after $duration \
        --ca intermediate1-cert.pem \
        --ca-key intermediate1-key.pem \
        --ca-password-file password.file \
        intermediate2 \
        intermediate2-cert.pem \
        intermediate2-key.pem \
   
    rm intermediate1-key.pem
    rm intermediate2.tpl

    # Chain certificates together and delete unneeded ones
    cat intermediate2-cert.pem intermediate1-cert.pem root-cert.pem > intermediate-3-cert.pem
    mv intermediate2-key.pem intermediate-3-key.pem
    rm intermediate2-cert.pem intermediate1-cert.pem root-cert.pem 

    rm password.file
}

function generate_eku_chaining_violation {
     echo $password > password.file
    
    # Root CA
    cat <<-EOF > root.tpl
    {
        "subject": {
            "commonName": "root"
        },
        "issuer": {
            "commonName": "root"
        },
        "keyUsage": ["certSign", "crlSign"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 2
        }
    }
EOF

    step certificate create \
        --template root.tpl \
        --password-file password.file \
        --not-after $duration \
        root \
        root-cert.pem \
        root-key.pem \
    
    rm root.tpl

    # Intermediate 1
    # NB: This intermediate lacks code signing extended key usage so its in
    # violation of extended key usage chaining a should _not_ load.
    cat <<-EOF > intermediate1.tpl
    {
        "subject": {
            "commonName": "intermediate1"
        },
        "keyUsage": ["certSign", "crlSign"],
        "extKeyUsage": ["codeSigning"],
        "basicConstraints": {
            "isCA": true,
            "maxPathLen": 1
        }
    }
EOF
    
    step certificate create \
        --template intermediate1.tpl \
        --password-file password.file \
        --not-after $duration \
        --kty OKP \
        --curve Ed25519 \
        --ca root-cert.pem \
        --ca-key root-key.pem \
        --ca-password-file password.file \
        intermediate1 \
        intermediate1-cert.pem \
        intermediate1-key.pem \
   
    rm root-key.pem 
    rm intermediate1.tpl

    # Intermediate 2
    # NB: This intermediate lacks code signing extended key usage so its in
    # violation of extended key usage chaining a should _not_ load.
    cat <<-EOF > intermediate2.tpl
    {
        "subject": {
            "commonName": "intermediate2"
        },
        "keyUsage": ["certSign", "crlSign"],
        "basicConstraints": {
            "isCA": true
        }
    }
EOF
    
    step certificate create \
        --template intermediate2.tpl \
        --password-file password.file \
        --not-after $duration \
        --ca intermediate1-cert.pem \
        --ca-key intermediate1-key.pem \
        --ca-password-file password.file \
        intermediate2 \
        intermediate2-cert.pem \
        intermediate2-key.pem \
   
    rm intermediate1-key.pem
    rm intermediate2.tpl

    # Chain certificates together and delete unneeded ones
    cat intermediate2-cert.pem intermediate1-cert.pem root-cert.pem > eku-chaining-violation-cert.pem
    mv intermediate2-key.pem eku-chaining-violation-key.pem
    rm intermediate2-cert.pem intermediate1-cert.pem root-cert.pem 

    rm password.file
}

generate_ed25519 
generate_ecdsa
generate_rsa4096
generate_openssl
generate_key_mismatch
generate_not_a_ca
generate_intermediate_2_ca
generate_intermediate_3_ca
generate_eku_chaining_violation
