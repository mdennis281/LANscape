# LANscape

A local network scanner with a built-in web UI. Discover devices, open ports, and running services on your network.

> The UI was recently converted into react, stored in a separate repo: [mdennis281/lanscape-ui](https://github.com/mdennis281/lanscape-ui)

```sh
pip install lanscape
python -m lanscape
```

Stats: 

![Version](https://img.shields.io/pypi/v/lanscape)
![Monthly Downloads](https://img.shields.io/pypi/dm/lanscape)
![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fmdennis281%2Flanscape-blue?logo=docker)

Latest release: 

![Stable](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=releases%2F*&label=Stable)
![RC](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=pre-releases%2F*rc*&label=RC)
![Beta](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=pre-releases%2F*b*&label=Beta)

Health: 

![pytest](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test.yml?branch=main&label=pytest) 
![packaging](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test-package.yml?label=packaging) 
![pylint](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/pylint.yml?branch=main&label=pylint)

---

![LANscape UI](https://github.com/mdennis281/LANscape/raw/main/docs/img/lanscape-ui-main.jpg)

<details>
<summary>More screenshots</summary>

![Scan Configuration](https://github.com/mdennis281/LANscape/raw/main/docs/img/lanscape-config.png)

![Port Detail](https://github.com/mdennis281/LANscape/raw/main/docs/img/lanscape-port-detail.jpg)

</details>

---

## Flags

| Flag | Description |
|------|-------------|
| `--version` | Show the installed version and exit |
| `--ui-port <number>` | Port for the web UI (default: auto) |
| `--ws-port <number>` | Port for the WebSocket server (default: 8766) |
| `--ws-server` | Start WebSocket server only (no UI) |
| `--persistent` | Don't auto-shutdown when the browser tab closes |
| `--mdns-off` | Disable mDNS service discovery |
| `--logfile <path>` | Write log output to a file |
| `--loglevel <level>` | Set log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO) |
| `--debug` | Shorthand for `--loglevel DEBUG` |

```sh
python -m lanscape
python -m lanscape --version
python -m lanscape --ui-port 8080
python -m lanscape --debug --persistent
python -m lanscape --logfile /tmp/lanscape.log --loglevel WARNING
python -m lanscape --ws-server --ws-port 9000
```


## Docker (Linux Only)

Docker is recommended for **Linux hosts only**. Network scanning requires `--network host` mode, which only works properly on Linux. For Windows/Mac, use `pip install lanscape` instead.

```sh
docker run -d --name lanscape \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape:latest
```

Or use Docker Compose:

```sh
curl -O https://raw.githubusercontent.com/mdennis281/LANscape/main/docker-compose.yml
docker compose up -d
```

Access the UI at `http://localhost:5001`

### Custom Ports

To use different ports, set the environment variables. When using `--network host` (as below), Docker ignores `-p`, so only the environment variables are needed. In bridge mode, you must also publish the matching ports with `-p`/`ports:`.

```sh
docker run -d --name lanscape \
  --network host \
  -e LANSCAPE_UI_PORT=8080 \
  -e LANSCAPE_WS_PORT=8081 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  ghcr.io/mdennis281/lanscape:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LANSCAPE_UI_PORT` | `5001` | Web UI port |
| `LANSCAPE_WS_PORT` | `8766` | WebSocket server port |
| `LANSCAPE_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LANSCAPE_MDNS` | `true` | Enable mDNS discovery (`true`/`false`) |
| `LANSCAPE_WS_ONLY` | `false` | WebSocket-only mode (`true`/`false`) |
| `LANSCAPE_LOG_FILE` | | Path to log file (optional) |

> **Note:** Network scanning requires `--network host` mode for ARP/device discovery. Without it, you won't see MAC addresses/hostnames

## Troubleshooting

### MAC Address / Manufacturer is inaccurate or unknown
LANscape does an ARP lookup to determine MAC addresses. This can require
elevated permissions to get accurate results — try running your shell as admin.

### Scan accuracy seems low
The scanner uses a combination of ARP, ICMP, and port probing to find devices.
If results aren't great out of the box:

- Tweak the scan configuration preset (accessible from the gear icon)
- Set up ARP lookup properly — see [ARP issues](https://github.com/mdennis281/LANscape/blob/main/docs/arp-issues.md)
- Open an issue if something still seems off

### Something else
Feel free to [submit an issue](https://github.com/mdennis281/LANscape/issues) with details about what you're seeing.


