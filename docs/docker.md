# Docker Setup (Linux Only)

LANscape is available as a Docker image for Linux hosts. Because network scanning requires direct access to the LAN (ARP, ICMP, broadcast traffic), Docker's network isolation works against you here — **`--network host` mode is required**, and that only works on Linux.

> **Windows / macOS users:** Docker Desktop runs containers inside a Linux VM, so `--network host` exposes the VM's network — not your physical LAN. Use `pip install lanscape` or the [Electron app](https://github.com/mdennis281/lanscape-ui) instead.

---

## Images

| Architecture | Image | Platforms |
|-------------|-------|-----------|
| **AMD64** (x86_64) | `ghcr.io/mdennis281/lanscape:latest` | Most servers, desktops |
| **ARM64** (aarch64) | `ghcr.io/mdennis281/lanscape-arm:latest` | Raspberry Pi, Apple Silicon, AWS Graviton |

---

## Quick Start

**AMD64:**
```sh
docker run -d --name lanscape \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape:latest
```

**ARM64:**
```sh
docker run -d --name lanscape \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape-arm:latest
```

Or use Docker Compose:

```sh
curl -O https://raw.githubusercontent.com/mdennis281/LANscape/main/docker/docker-compose.yml
docker compose up -d                              # AMD64 (default)
docker compose --profile arm64 up -d lanscape-arm # ARM64
```

Access the UI at `http://localhost:5001`

---

## Custom Ports

To use different ports, set the environment variables. When using `--network host`, Docker ignores `-p`, so only the environment variables are needed. In bridge mode, you must also publish the matching ports with `-p`/`ports:`.

```sh
docker run -d --name lanscape \
  --network host \
  -e LANSCAPE_UI_PORT=8080 \
  -e LANSCAPE_WS_PORT=8081 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape:latest
```

---

## Required Ports

LANscape uses two ports that must be reachable for the UI and live scan updates to work:

| Port | Purpose |
|------|---------|
| `5001` | Web UI (HTTP) |
| `8766` | WebSocket (live scan data) |

With `--network host` (Linux), both ports are automatically available on the host — no extra flags needed.

In **bridge mode** (or Docker Desktop on Windows/Mac), you must publish them explicitly:

```sh
docker run -d --name lanscape \
  -p 5001:5001 \
  -p 8766:8766 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape:latest
```

> **Note:** Bridge mode limits scanning to TCP port probing only — ARP/ICMP device discovery requires `--network host` on Linux.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LANSCAPE_UI_PORT` | `5001` | Web UI port |
| `LANSCAPE_WS_PORT` | `8766` | WebSocket server port |
| `LANSCAPE_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LANSCAPE_MDNS` | `true` | Enable mDNS discovery (`true`/`false`) |
| `LANSCAPE_WS_ONLY` | `false` | WebSocket-only mode (`true`/`false`) |
| `LANSCAPE_LOG_FILE` | `None` | Path to log file (optional) |

If you change `LANSCAPE_UI_PORT` or `LANSCAPE_WS_PORT`, update your `-p` mappings (bridge mode) or firewall rules accordingly.
