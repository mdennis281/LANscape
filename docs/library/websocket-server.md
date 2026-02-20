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
| `subnet` | `string` | yes | Target subnet (e.g. `"192.168.1.0/24"`) |
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
| `subnet` | `string` | yes | Subnet to validate (e.g. `"192.168.1.0/24"`) |

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
  { "subnet": "192.168.1.0/24", "interface": "eth0", "description": "..." }
]
```

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
