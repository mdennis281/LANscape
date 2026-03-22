# Nginx with self-signed TLS for integration testing
FROM nginx:alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl

# Generate self-signed certificate at build time
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/CN=web-server/O=LANscape-Test/C=US" \
        2>/dev/null

COPY default.conf /etc/nginx/conf.d/default.conf
