#!/bin/bash
set -e

# Build command arguments from environment variables
ARGS="--persistent"  # Always persistent in container

# Port configuration
ARGS="$ARGS --ui-port ${LANSCAPE_UI_PORT:-5001}"
ARGS="$ARGS --ws-port ${LANSCAPE_WS_PORT:-8766}"

# Log level
ARGS="$ARGS --loglevel ${LANSCAPE_LOG_LEVEL:-INFO}"

# mDNS toggle
if [ "${LANSCAPE_MDNS}" = "false" ]; then
    ARGS="$ARGS --mdns-off"
fi

# WebSocket-only mode
if [ "${LANSCAPE_WS_ONLY}" = "true" ]; then
    ARGS="$ARGS --ws-server"
fi

# Log file (optional)
if [ -n "${LANSCAPE_LOG_FILE}" ]; then
    ARGS="$ARGS --logfile ${LANSCAPE_LOG_FILE}"
fi

# Execute the command
if [ "$1" = "lanscape" ]; then
    exec lanscape $ARGS
else
    exec "$@"
fi
