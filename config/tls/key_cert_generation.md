# Generation of ct_server key/cert and CA certficate

## Commands

```
# 1. Generate CA's private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -days 36500 -nodes -keyout ca.key -out ca.crt -subj "/CN=My CA"

# 2. Generate ct_server's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout tls.key -out server-req.pem -subj "/=Server TLS/OU=Server/CN=*/emailAddress=tls@gmail.com"

# 3. SAN
echo "subjectAltName=DNS:*,DNS:ct_server,IP:0.0.0.0" > server-ext.cnf

# 3. Use CA's private key to sign ct_server's CSR and get back the signed certificate
openssl x509 -req -in server-req.pem -days 36500 -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -extfile server-ext.cnf

# 4. Clean-up 
rm ca.key ca.srl server-ext.cnf server-req.pem

```
