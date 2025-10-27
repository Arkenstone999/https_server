#!/bin/bash
set -e

mkdir -p certs

# Create OpenSSL config file with Subject Alternative Name
cat > certs/openssl.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate certificate with SAN extension
openssl req -x509 -newkey rsa:4096 \
    -keyout certs/key.pem \
    -out certs/cert.pem \
    -days 365 \
    -nodes \
    -config certs/openssl.cnf

# Set proper permissions
chmod 600 certs/key.pem
chmod 644 certs/cert.pem

# Clean up config file
rm certs/openssl.cnf

echo "✓ TLS certificates generated successfully"
echo "  Certificate: certs/cert.pem"
echo "  Private key: certs/key.pem"
echo ""
echo "Certificate details:"
openssl x509 -in certs/cert.pem -noout -subject -dates -ext subjectAltName