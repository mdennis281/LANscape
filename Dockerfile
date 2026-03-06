# LANscape Docker Image
# Single-stage build - installs from PyPI for simplicity and consistency

ARG VERSION=latest

FROM python:3.12-slim

LABEL org.opencontainers.image.title="LANscape"
LABEL org.opencontainers.image.description="A Python-based local network scanner with web UI"
LABEL org.opencontainers.image.source="https://github.com/mdennis281/LANscape"
LABEL org.opencontainers.image.licenses="MIT"

# Install runtime dependencies for network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install lanscape from PyPI
# Use explicit version since pypi occasionally has propagation delays
ARG VERSION
RUN pip install --no-cache-dir "lanscape==${VERSION}"

# Environment variables for configuration
ENV LANSCAPE_UI_PORT=5001
ENV LANSCAPE_WS_PORT=8766
ENV LANSCAPE_LOG_LEVEL=INFO
ENV LANSCAPE_MDNS=true

# Expose default ports
EXPOSE 5001 8766

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://localhost:%s/' % os.environ.get('LANSCAPE_UI_PORT', '5001'))" || exit 1

# Create non-root user for running LANscape
RUN useradd -m -r -s /bin/bash lanscape && chown -R lanscape:lanscape /app

# Entry point script to handle env vars
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER lanscape

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["lanscape"]
