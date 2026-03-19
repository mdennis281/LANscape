# Multi-service container for integration testing
# Runs SSH + HTTP + HTTPS on a single host

FROM alpine:3.20

RUN apk add --no-cache \
    openssh-server \
    nginx \
    openssl \
    supervisor

# Generate SSH host keys
RUN ssh-keygen -A && \
    echo "root:testpass" | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Generate self-signed cert for HTTPS
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/CN=multi-service/O=LANscape-Test/C=US" \
        2>/dev/null

# Nginx config: HTTP (80) + HTTPS (443)
RUN printf 'server {\n\
    listen 80 default_server;\n\
    listen [::]:80 default_server;\n\
    location / { return 200 "multi-service HTTP\\n"; }\n\
}\n\
server {\n\
    listen 443 ssl default_server;\n\
    listen [::]:443 ssl default_server;\n\
    ssl_certificate /etc/nginx/ssl/server.crt;\n\
    ssl_certificate_key /etc/nginx/ssl/server.key;\n\
    location / { return 200 "multi-service HTTPS\\n"; }\n\
}\n' > /etc/nginx/http.d/default.conf

# Supervisor config to run both services
RUN printf '[supervisord]\nnodaemon=true\nlogfile=/dev/null\nlogfile_maxbytes=0\n\n\
[program:sshd]\ncommand=/usr/sbin/sshd -D\nautorestart=true\n\n\
[program:nginx]\ncommand=nginx -g "daemon off;"\nautorestart=true\n' \
    > /etc/supervisord.conf

EXPOSE 22 80 443

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
