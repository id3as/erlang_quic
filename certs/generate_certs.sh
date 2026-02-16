#!/bin/bash
#
# Generate self-signed certificates for QUIC E2E testing
#
# This script generates:
# - CA certificate (ca.pem)
# - Server certificate (cert.pem)
# - Server private key (priv.key)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Certificate validity (days)
VALIDITY=365

# Key size
KEY_SIZE=2048

echo "Generating certificates in $SCRIPT_DIR"

# Generate CA private key
echo "Generating CA private key..."
openssl genrsa -out ca.key $KEY_SIZE 2>/dev/null

# Generate CA certificate
echo "Generating CA certificate..."
openssl req -new -x509 -days $VALIDITY -key ca.key -out ca.pem \
    -subj "/C=US/ST=Test/L=Test/O=QUIC Test CA/CN=QUIC Test CA" 2>/dev/null

# Generate server private key
echo "Generating server private key..."
openssl genrsa -out priv.key $KEY_SIZE 2>/dev/null

# Generate server CSR
echo "Generating server CSR..."
openssl req -new -key priv.key -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=QUIC Test/CN=localhost" 2>/dev/null

# Create extensions file for SAN
cat > server_ext.cnf << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = quic-server
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server certificate signed by CA
echo "Generating server certificate..."
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out cert.pem -days $VALIDITY \
    -extfile server_ext.cnf 2>/dev/null

# Clean up temporary files
rm -f server.csr server_ext.cnf ca.srl ca.key

# Set permissions
chmod 644 ca.pem cert.pem
chmod 600 priv.key

echo ""
echo "Certificates generated successfully:"
echo "  CA certificate:     $SCRIPT_DIR/ca.pem"
echo "  Server certificate: $SCRIPT_DIR/cert.pem"
echo "  Server private key: $SCRIPT_DIR/priv.key"
echo ""
echo "Certificate details:"
openssl x509 -in cert.pem -noout -subject -dates 2>/dev/null
echo ""
echo "Subject Alternative Names:"
openssl x509 -in cert.pem -noout -ext subjectAltName 2>/dev/null || true
