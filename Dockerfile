# LANscape Docker Image
# Multi-stage build for minimal image size

# Build stage - extract React UI from PyPI package
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir build

# Copy source and build wheel
COPY . .
RUN python -m build --wheel

# Runtime stage
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

# Install from built wheel
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create non-root user (network scanning needs root, but we can drop privs later if needed)
# For now, running as root is required for raw socket access

# Environment variables for configuration
ENV LANSCAPE_UI_PORT=5001
ENV LANSCAPE_WS_PORT=8766
ENV LANSCAPE_LOG_LEVEL=INFO
ENV LANSCAPE_MDNS=true

# Expose default ports
EXPOSE 5001 8766

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${LANSCAPE_UI_PORT}/')" || exit 1

# Entry point script to handle env vars
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["lanscape"]
