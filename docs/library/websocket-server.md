# WebSocket Server

LANscape includes a built-in WebSocket server that exposes all scanning, port management, and utility functionality over a persistent connection with real-time push updates.

## Quick Start

From module:
```sh
# start lanscape module without a UI
python -m lanscape --ws-server
```

From the code:
```python
from lanscape.ui.ws import WebSocketServer, run_server

# Option 1: Blocking convenience function
run_server(host="127.0.0.1", port=8766)

# Option 2: Async control
import asyncio

async def main():
    server = WebSocketServer(host="0.0.0.0", port=8766)
    await server.start()
    # ... your logic ...
    await server.stop()

asyncio.run(main())
```

Connect from any WebSocket client:

```
ws://127.0.0.1:8766
```

---

## Protocol

All messages are JSON. There are four message types:

### Request (client → server)

```json
{
  "type": "request",
  "id": "optional-correlation-id",
  "action": "scan.start",
  "params": { "subnet": "192.168.1.0/24", "port_list": "medium" }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | `"request"` | yes | Always `"request"` |
| `id` | `string` | no | Echoed back in the response for correlation |
| `action` | `string` | yes | The action to invoke (see [Actions](#actions) below) |
| `params` | `object` | no | Parameters for the action |

### Response (server → client)

```json
{
  "type": "response",
  "id": "optional-correlation-id",
  "action": "scan.start",
  "data": { "scan_id": "abc-123", "status": "running" },
  "success": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | `"response"` | Always `"response"` |
| `id` | `string` | Echoed from the request |
| `action` | `string` | The action that was handled |
| `data` | `any` | Response payload |
| `success` | `boolean` | `true` if the action succeeded |

### Error (server → client)

```json
{
  "type": "error",
  "id": "optional-correlation-id",
  "action": "scan.start",
  "error": "Scan not found: xyz",
  "traceback": "..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | `"error"` | Always `"error"` |
| `id` | `string` | Echoed from the request (if present) |
| `action` | `string` | The action that failed |
| `error` | `string` | Human-readable error message |
| `traceback` | `string` | Full Python traceback (debug) |

### Event (server → client, push)

```json
{
  "type": "event",
  "event": "scan.update",
  "data": { "scan_id": "abc-123", "devices": [...], "metadata": {...} }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | `"event"` | Always `"event"` |
| `event` | `string` | Event name (see [Events](#events) below) |
| `data` | `any` | Event payload |

---

## Connection Lifecycle

On connect the server sends a `connection.established` event:

```json
{
  "type": "event",
  "event": "connection.established",
  "data": {
    "client_id": "uuid-string",
    "actions": ["scan.start", "scan.get", "port.list", "..."]
  }
}
```

Save the `client_id` — you'll need it for `scan.subscribe` and `scan.get_delta`.

---

## Actions

### Scan Actions

#### `scan.start`

Start a new network scan (non-blocking).

**Params** — any [ScanConfig](config/scan-config.md) field:

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `subnet` | `string` | yes | Target subnet — IPv4 or IPv6 (e.g. `"192.168.1.0/24"`, `"fd00::/120"`, `"fd00::1-fd00::ff"`) |
| `port_list` | `string` | no | Port list name (`"small"`, `"medium"`, `"large"`, or custom) |
| `lookup_type` | `string[]` | no | Discovery methods (e.g. `["ICMP_THEN_ARP"]`) |
| `t_multiplier` | `int` | no | Thread multiplier |
| `task_scan_ports` | `bool` | no | Enable port scanning |
| `task_scan_port_services` | `bool` | no | Enable service detection |
| *...other* | | no | See [ScanConfig](config/scan-config.md) for all fields |

**Response data:**

```json
{ "scan_id": "abc-123", "status": "running" }
```

---

#### `scan.start_sync`

Start a scan and wait until it completes before responding. Same params as `scan.start`.

**Response data:**

```json
{ "scan_id": "abc-123", "status": "complete" }
```

---

#### `scan.get`

Get full scan results.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |

**Response data:** Full [ScanResults](models/overview.md) object (devices, metadata, etc.)

---

#### `scan.get_delta`

Get only data that changed since the last call (per client). Ideal for polling or supplementing subscriptions.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |
| `client_id` | `string` | no | Client identifier (defaults to `"default"`) |

**Response data:**

```json
{
  "scan_id": "abc-123",
  "running": true,
  "has_changes": true,
  "devices": [ { "ip": "192.168.1.5", "alive": true, "hostname": "router", ... } ],
  "metadata": {
    "percent_complete": 0.45,
    "stage": "port_scan",
    "...": "..."
  }
}
```

Only devices and metadata that changed since the last call are included.

---

#### `scan.summary`

Get a lightweight progress summary.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |

**Response data:** [ScanSummary](models/overview.md#scansummary)

---

#### `scan.terminate`

Stop a running scan.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |

**Response data:**

```json
{ "success": true, "scan_id": "abc-123" }
```

---

#### `scan.subscribe`

Subscribe to real-time push updates for a scan. The server will send `scan.update` events every ~500ms with delta data.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |
| `client_id` | `string` | yes | Your client ID (from `connection.established`) |

**Response data:**

```json
{ "subscribed": true, "scan_id": "abc-123", "client_id": "uuid" }
```

---

#### `scan.unsubscribe`

Unsubscribe from scan updates.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |
| `client_id` | `string` | yes | Your client ID |

**Response data:**

```json
{ "unsubscribed": true, "scan_id": "abc-123", "client_id": "uuid" }
```

---

#### `scan.list`

List all scans (active and completed).

**Params:** none

**Response data:** Array of scan list items with `scan_id`, `subnet`, `running`, `stage`, etc.

---

#### `scan.get_port_detail`

Get detailed service-probe results for a specific port on a discovered device. Returns every probe/response pair collected during the service scan, useful for inspecting *how* a service was identified.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | `string` | yes | The scan ID |
| `ip` | `string` | yes | Device IP address |
| `port` | `int` | yes | Port number to inspect |

**Response data:**

```json
{
  "port": 443,
  "service": "HTTPS",
  "probes_sent": 5,
  "probes_received": 2,
  "is_tls": true,
  "responses": [
    {
      "response": "HTTP/1.1 200 OK...",
      "service": "HTTPS",
      "probes": ["GET / HTTP/1.1..."],
      "is_tls": true
    }
  ]
}
```

| Response field | Type | Description |
|----------------|------|-------------|
| `port` | `int` | The requested port |
| `service` | `string` | Best-match service name |
| `probes_sent` | `int` | Total probes sent across all attempts |
| `probes_received` | `int` | Total responses received |
| `is_tls` | `bool` | Whether any probe detected TLS |
| `responses` | `array` | Individual probe/response groups (see below) |

Each entry in `responses`:

| Field | Type | Description |
|-------|------|-------------|
| `response` | `string \| null` | Raw response text |
| `service` | `string` | Service identified for this response |
| `probes` | `string[]` | Probe payloads that produced this response |
| `is_tls` | `bool` | Whether TLS was used for this probe |

If the port has no service info (e.g. it was open but unprobed), `responses` will be an empty array with zeroed counters.

---

### Port Actions

#### `port.list`

Get all available port list names.

**Params:** none

**Response data:**

```json
["small", "medium", "large"]
```

---

#### `port.list_summary`

Get port lists with their port counts.

**Params:** none

**Response data:**

```json
[
  { "name": "small", "count": 25 },
  { "name": "medium", "count": 135 },
  { "name": "large", "count": 1000 }
]
```

---

#### `port.get`

Get a specific port list.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | yes | Port list name |

**Response data:** Object mapping port numbers to service names:

```json
{ "22": "ssh", "80": "http", "443": "https" }
```

---

#### `port.create`

Create a new port list.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | yes | Name for the new list |
| `ports` | `object` | yes | Port-to-service mapping (e.g. `{"8080": "http-alt"}`) |

**Response data:**

```json
{ "success": true, "name": "my-list" }
```

---

#### `port.update`

Update an existing port list.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | yes | Port list name |
| `ports` | `object` | yes | New port-to-service mapping |

**Response data:**

```json
{ "success": true, "name": "my-list" }
```

---

#### `port.delete`

Delete a port list.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | yes | Port list name |

**Response data:**

```json
{ "success": true, "name": "my-list" }
```

---

### Tools Actions

#### `tools.subnet_test`

Validate a subnet string and get its host count.

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `subnet` | `string` | yes | Subnet to validate — IPv4 or IPv6 (e.g. `"192.168.1.0/24"`, `"fd00::/120"`) |

**Response data:**

```json
{ "valid": true, "msg": "254 IPs", "count": 254 }
```

On failure:

```json
{ "valid": false, "msg": "invalid subnet", "error": "...", "count": -1 }
```

---

#### `tools.subnet_list`

List all network subnets detected on the host machine. The primary subnet is sorted first.

**Params:** none

**Response data:** Array of subnet info objects:

```json
[
  { "subnet": "192.168.1.0/24", "address_cnt": 254, "interface": "eth0" },
  { "subnet": "fd00::/64", "address_cnt": 18446744073709551614, "interface": "eth0" }
]
```

Each object includes:

| Key | Type | Description |
|-----|------|-------------|
| `subnet` | `string` | Subnet in CIDR notation |
| `address_cnt` | `int` | Number of hosts in the subnet |
| `interface` | `string` | Network interface name (e.g., `"eth0"`, `"Wi-Fi"`) |

---

#### `tools.config_defaults`

Get the built-in scan configuration presets. ARP-dependent presets are automatically adjusted if ARP is not supported.

**Params:** none

**Response data:** Object mapping preset names to [ScanConfig](config/scan-config.md) dicts:

```json
{
  "balanced": { "port_list": "medium", "lookup_type": ["ICMP_THEN_ARP"], "..." },
  "accurate": { "..." },
  "fast": { "..." }
}
```

---

#### `tools.arp_supported`

Check if ARP scanning is available on the current system.

**Params:** none

**Response data:**

```json
{ "supported": true }
```

---

#### `tools.app_info`

Get application version, runtime arguments, and update status.

**Params:** none

**Response data:**

```json
{
  "name": "LANscape",
  "version": "3.0.1",
  "arp_supported": true,
  "update_available": false,
  "latest_version": "3.0.1",
  "runtime_args": {
    "port": 11000,
    "ws_port": 8766,
    "loglevel": "INFO",
    "persistent": false
  }
}
```

---

## Events

Events are server-initiated push messages. You receive them after subscribing to a scan.

| Event | Description | Data |
|-------|-------------|------|
| `connection.established` | Sent on connect | `{ client_id, actions[] }` |
| `scan.update` | Delta update for a running scan (~500ms) | `{ scan_id, running, has_changes, devices[], metadata }` |
| `scan.complete` | Scan finished successfully | Final delta with `metadata.running = false` |
| `scan.terminated` | Scan was terminated by the user | Final delta with `metadata.stage = "terminated"` |

### Delta Updates

The server uses content hashing to track what each client has already seen. `scan.update` events only contain **changed** devices and metadata — not the full result set. This keeps bandwidth low during large scans.

The delta payload matches `scan.get_delta` response format:

```json
{
  "scan_id": "abc-123",
  "running": true,
  "has_changes": true,
  "devices": [],
  "metadata": {
    "percent_complete": 0.72,
    "stage": "port_scan",
    "devices_total": 254,
    "devices_scanned": 183,
    "devices_alive": 12
  }
}
```

---

## Full Example

```python
import asyncio
import json
import websockets

async def main():
    async with websockets.connect("ws://127.0.0.1:8766") as ws:
        # 1. Receive welcome event
        welcome = json.loads(await ws.recv())
        client_id = welcome["data"]["client_id"]
        print(f"Connected as {client_id}")

        # 2. Start a scan
        await ws.send(json.dumps({
            "type": "request",
            "id": "1",
            "action": "scan.start",
            "params": {"subnet": "192.168.1.0/24", "port_list": "small"}
        }))
        resp = json.loads(await ws.recv())
        scan_id = resp["data"]["scan_id"]

        # 3. Subscribe to live updates
        await ws.send(json.dumps({
            "type": "request",
            "id": "2",
            "action": "scan.subscribe",
            "params": {"scan_id": scan_id, "client_id": client_id}
        }))
        await ws.recv()  # subscription confirmation

        # 4. Listen for updates until scan completes
        while True:
            msg = json.loads(await ws.recv())
            if msg["type"] == "event":
                if msg["event"] == "scan.update":
                    meta = msg["data"].get("metadata", {})
                    pct = meta.get("percent_complete", 0)
                    print(f"Progress: {pct:.0%}")
                elif msg["event"] in ("scan.complete", "scan.terminated"):
                    print(f"Scan finished: {msg['event']}")
                    break

        # 5. Get full results
        await ws.send(json.dumps({
            "type": "request",
            "id": "3",
            "action": "scan.get",
            "params": {"scan_id": scan_id}
        }))
        results = json.loads(await ws.recv())
        for device in results["data"]["devices"]:
            print(f"  {device['ip']} - {device.get('hostname', '?')}")

asyncio.run(main())
```

---

## Server Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | `127.0.0.1` | Bind address |
| `port` | `8766` | WebSocket port |
| `on_client_change` | `None` | Callback `(int) -> None` fired when client count changes |

```python
server = WebSocketServer(
    host="0.0.0.0",
    port=9000,
    on_client_change=lambda count: print(f"{count} clients connected")
)
```

---

## HTTP API

When running the built-in web server (`start_webapp_server`), a lightweight HTTP API is available alongside the WebSocket server.

### `GET /api/discover`

Returns connection info for this server and any other LANscape instances discovered on the local network via mDNS.

**Response:**

```json
{
  "mdns_enabled": true,
  "default_route": "http://192.168.1.50:5001",
  "instances": [
    {
      "host": "192.168.1.100",
      "ws_port": 8766,
      "http_port": 5001,
      "version": "3.1.0",
      "hostname": "server-2"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mdns_enabled` | `bool` | Whether mDNS discovery is active on this server |
| `default_route` | `string` | Preferred connection URL for this server (uses LAN IP when available) |
| `instances` | `array` | Other LANscape instances found via mDNS (empty when mDNS is disabled or no peers found) |

Each instance entry:

| Field | Type | Description |
|-------|------|-------------|
| `host` | `string` | IP address of the discovered instance |
| `ws_port` | `int` | WebSocket port |
| `http_port` | `int` | HTTP port |
| `version` | `string` | LANscape version running on that instance |
| `hostname` | `string` | Machine hostname |

---

## mDNS Discovery

The server can advertise itself on the local network and discover other LANscape instances using mDNS/DNS-SD (service type `_lanscape._tcp.local.`). This is managed by the `DiscoveryService` class.

mDNS is **enabled by default**. Disable it with the `--mdns-off` CLI flag:

```bash
python -m lanscape --mdns-off
```

When disabled, `/api/discover` still responds but with `mdns_enabled: false` and an empty `instances` list.

---

## CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--port` | `5001` | HTTP server port |
| `--ws-port` | `8766` | WebSocket server port |
| `--loglevel` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `--debug` | — | Shorthand for `--loglevel DEBUG` |
| `--persistent` | — | Don't auto-shutdown when browser closes |
| `--ws-server` | — | Start WebSocket server only (no UI) |
| `--mdns-off` | — | Disable mDNS service discovery |
| `--logfile` | — | Log output to the specified file path |
