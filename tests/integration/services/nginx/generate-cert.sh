#!/bin/sh
# Generate self-signed certificate for HTTPS testing
set -e

CERT_DIR="/etc/nginx/ssl"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ]; then
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -subj "/CN=web-server/O=LANscape-Test/C=US" \
        2>/dev/null
    echo "Self-signed certificate generated."
fi
