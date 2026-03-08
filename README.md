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

Latest release: 

![Stable](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=releases%2F*&label=Stable)
![RC](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=pre-releases%2F*rc*&label=RC)
![Beta](https://img.shields.io/github/v/tag/mdennis281/LANScape?filter=pre-releases%2F*b*&label=Beta)

Docker: 

![lanscape](https://ghcr-badge.egpl.dev/mdennis281/lanscape/latest_tag?label=lanscape%20%28amd64%29&ignore=*rc*,*b*,*a*,*latest*)
![lanscape-arm](https://ghcr-badge.egpl.dev/mdennis281/lanscape-arm/latest_tag?label=lanscape-arm%20%28arm64%29&ignore=*rc*,*b*,*a*,*latest*)

Health: 

![pytest](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test.yml?branch=main&label=pytest) 
![pylint](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/pylint.yml?branch=main&label=pylint)
![packaging](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test-package.yml?label=pypi%20pkg) 
![docker](https://img.shields.io/github/actions/workflow/status/mdennis281/LANscape/test-docker.yml?label=docker%20pkg)

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

> **Not recommended for most users.** Network scanning requires direct LAN access (ARP, ICMP, broadcasts), which conflicts with Docker's network isolation. The Docker image requires `--network host` mode, which **only works on Linux** — on Windows and macOS, Docker Desktop runs inside a VM so `--network host` exposes the VM's network, not your physical LAN.
>
> For most users, `pip install lanscape` is the better option.

If you're running on a Linux host and still want to use Docker, see the full setup guide: **[Docker Setup Instructions](docs/docker.md)**


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


