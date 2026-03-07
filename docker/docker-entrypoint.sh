#!/bin/bash
set -e

# Build command arguments as array to prevent word-splitting/injection
args=("--persistent")  # Always persistent in container

# Port configuration
args+=("--ui-port" "${LANSCAPE_UI_PORT:-5001}")
args+=("--ws-port" "${LANSCAPE_WS_PORT:-8766}")

# Log level
args+=("--loglevel" "${LANSCAPE_LOG_LEVEL:-INFO}")

# mDNS toggle
if [ "${LANSCAPE_MDNS}" = "false" ]; then
    args+=("--mdns-off")
fi

# WebSocket-only mode
if [ "${LANSCAPE_WS_ONLY}" = "true" ]; then
    args+=("--ws-server")
fi

# Log file (optional)
if [ -n "${LANSCAPE_LOG_FILE}" ]; then
    args+=("--logfile" "${LANSCAPE_LOG_FILE}")
fi

# Execute the command
if [ "$1" = "lanscape" ]; then
    exec lanscape "${args[@]}"
else
    exec "$@"
fi
