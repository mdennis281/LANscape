FROM alpine:3.20

RUN apk add --no-cache squid netcat-openbsd

COPY squid.conf /etc/squid/squid.conf

EXPOSE 3128

CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
