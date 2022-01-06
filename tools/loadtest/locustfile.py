# Copyright 2022 The Sigstore Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from locust import HttpUser, task, constant_throughput, events
import jwt

@events.init_command_line_parser.add_listener
def _(parser):
    parser.add_argument("--token", type=str, env_var="LOCUST_OIDC_TOKEN", default="", help="OIDC token for authentication with Fulcio")
    parser.add_argument("--max-qps-per-user", type=float, env_var="LOCUST_MAX_QPS_PER_USER", default=1.0, help="Maximum QPS per user")

class FulcioUser(HttpUser):
    # FulcioUser represents an instance of a user making requests.

    # Maximum number of requests per second per user. For example, to reach 25 QPS,
    # run Locust with 25 users with a constant throughput of 1.
    def wait_time(self):
        return constant_throughput(self.environment.parsed_options.max_qps_per_user)(self)

    @task
    def create_cert(self):
        # create_cert generates a keypair and makes a request to Fulcio to fetch a certificate.

        # Static ID token. This avoids hitting the OIDC provider with each request to fetch a new token.
        token = self.environment.parsed_options.token

        # Generate keypair for challenge.
        privkey = ec.generate_private_key(ec.SECP256R1)
        pubkey = privkey.public_key()
        pubbytes = pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        content = base64.b64encode(pubbytes).decode("utf-8")

        # Fetch identity of token and sign.
        email = jwt.decode(token, options={"verify_signature":False})['email']
        data = email.encode()
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
        challenge = base64.b64encode(signature).decode("utf-8")

        json = {"publicKey": {"content": content,"algorithm":"ecdsa"},"signedEmailAddress":challenge}
        response = self.client.post("/api/v1/signingCert", json=json, headers={"Authorization": f"Bearer {token}", "Content-Type":"application/json"})
        print("Response status code:", response.status_code)
