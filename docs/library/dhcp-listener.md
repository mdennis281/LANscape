# DhcpListener

`lanscape.DhcpListener`

Passively captures DHCP traffic on the LAN and surfaces fully-parsed lease events — DISCOVERs, REQUESTs, OFFERs, ACKs, and more — via a callback interface.

Useful for:
- Watching new devices join the network in real time
- Troubleshooting DHCP failures (e.g. DISCOVER with no ACK)
- Auditing vendor class / hostname data sent by clients
- Monitoring which subnets are actively requesting leases

> **Privilege requirement:** Capturing on UDP ports 67/68 typically requires root / Administrator privileges. On Linux you can use `sudo`, on Windows run the process as Administrator.

## Import

```python
from lanscape import DhcpListener, DhcpListenerConfig, DhcpLeaseEvent, DhcpMessageType
```

---

## Quick Start

```python
from lanscape import DhcpListener, DhcpListenerConfig, DhcpMessageType

config = DhcpListenerConfig(
    subnet_filter=["192.168.1.0/24"],
    message_types=[DhcpMessageType.DISCOVER, DhcpMessageType.REQUEST],
)

def on_event(event):
    print(f"[{event.message_type.name}] {event.client_mac} → {event.effective_ip}")
    if event.hostname:
        print(f"  hostname : {event.hostname}")
    if event.vendor_class:
        print(f"  vendor   : {event.vendor_class}")

with DhcpListener(config, on_event=on_event):
    input("Listening for DHCP… press Enter to stop\n")
```

---

## DhcpListenerConfig

Configuration model for `DhcpListener`.

```python
from lanscape import DhcpListenerConfig, DhcpMessageType

config = DhcpListenerConfig(
    subnet_filter=["192.168.1.0/24", "10.0.0.0/8"],
    message_types=[DhcpMessageType.DISCOVER, DhcpMessageType.REQUEST],
    include_server_messages=False,
    interface="eth0",
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subnet_filter` | `List[str] \| None` | `None` | CIDR subnets to filter on. Only events where the client IP falls within one of these subnets are emitted. `None` = no filter (all events pass). |
| `message_types` | `List[DhcpMessageType] \| None` | `None` | Restrict to these message types. `None` captures all types. |
| `include_server_messages` | `bool` | `True` | When `False`, OFFER / ACK / NAK messages from the DHCP server are suppressed. |
| `interface` | `str \| None` | `None` | Network interface to listen on. `None` listens on all interfaces. |

---

## DhcpListener

### Constructor

```python
listener = DhcpListener(config: DhcpListenerConfig, on_event: Callable[[DhcpLeaseEvent], None])
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `config` | `DhcpListenerConfig` | Listener configuration |
| `on_event` | `Callable[[DhcpLeaseEvent], None]` | Callback invoked for each matching packet. Called from the sniffer thread — keep it fast or hand off to a queue. |

### Methods

#### `start() -> None`

Start the background sniffer. Raises `RuntimeError` if already running.

#### `stop() -> None`

Stop the sniffer and clean up resources. Safe to call when not running.

#### `is_running -> bool`

`True` while the sniffer thread is active.

### Context Manager

`DhcpListener` supports the context manager protocol:

```python
with DhcpListener(config, on_event=handler) as listener:
    # listener is running here
    time.sleep(60)
# listener is stopped automatically
```

---

## DhcpLeaseEvent

Pydantic model representing a single parsed DHCP packet. All optional fields are `None` when absent from the packet.

### Client identification

| Field | Type | Description |
|-------|------|-------------|
| `client_mac` | `str` | Client hardware (MAC) address from BOOTP `chaddr` |
| `client_ip` | `str \| None` | Client IP (`ciaddr`) — non-zero only when client already has a lease |
| `client_identifier` | `str \| None` | Option 61 — often MAC (formatted `aa:bb:cc:dd:ee:ff`) or UUID string |

### IP negotiation

| Field | Type | Description |
|-------|------|-------------|
| `requested_ip` | `str \| None` | Option 50 — IP the client is requesting |
| `offered_ip` | `str \| None` | `yiaddr` — IP offered or assigned by the server |
| `server_ip` | `str \| None` | `siaddr` — next-server IP from BOOTP header |
| `server_identifier` | `str \| None` | Option 54 — DHCP server IP |

### Client-supplied options

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | `str \| None` | Option 12 — client-supplied hostname |
| `fqdn` | `str \| None` | Option 81 (RFC 4702) — fully-qualified domain name |
| `vendor_class` | `str \| None` | Option 60 — vendor class identifier (e.g. `"MSFT 5.0"`, `"android-dhcp-13"`) |
| `user_class` | `str \| None` | Option 77 — user class information |
| `requested_options` | `List[int] \| None` | Option 55 — list of option codes the client wants in the response |

### Server-supplied lease parameters

| Field | Type | Description |
|-------|------|-------------|
| `subnet_mask` | `str \| None` | Option 1 — offered subnet mask |
| `router` | `str \| None` | Option 3 — default gateway |
| `dns_servers` | `List[str] \| None` | Option 6 — DNS server list |
| `lease_time` | `int \| None` | Option 51 — lease duration in seconds |
| `renewal_time` | `int \| None` | Option 58 — T1 renewal time in seconds |
| `rebinding_time` | `int \| None` | Option 59 — T2 rebinding time in seconds |

### Raw / transport

| Field | Type | Description |
|-------|------|-------------|
| `unknown_options` | `dict` | Code → `repr(value)` for any DHCP options not explicitly decoded |
| `src_ip` | `str \| None` | IP-layer source address of the captured packet |
| `dst_ip` | `str \| None` | IP-layer destination address |
| `interface` | `str \| None` | Network interface the packet was captured on |
| `timestamp` | `datetime` | UTC capture timestamp |
| `message_type` | `DhcpMessageType \| None` | Option 53 — DHCP message type |

### Computed properties

| Property | Type | Description |
|----------|------|-------------|
| `effective_ip` | `str \| None` | Best available client IP: `requested_ip` → `offered_ip` → `client_ip` |
| `is_client_message` | `bool` | `True` for DISCOVER / REQUEST / DECLINE / RELEASE / INFORM |
| `is_server_message` | `bool` | `True` for OFFER / ACK / NAK |

---

## DhcpMessageType

`IntEnum` with all 8 DHCP message types defined in RFC 2131.

```python
from lanscape import DhcpMessageType
```

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| `1` | `DISCOVER` | Client → Server | Client broadcasts to locate servers |
| `2` | `OFFER` | Server → Client | Server offers an IP address |
| `3` | `REQUEST` | Client → Server | Client requests offered or previously assigned address |
| `4` | `DECLINE` | Client → Server | Client declines the offered address (conflict) |
| `5` | `ACK` | Server → Client | Server confirms the lease |
| `6` | `NAK` | Server → Client | Server denies the request |
| `7` | `RELEASE` | Client → Server | Client releases its lease |
| `8` | `INFORM` | Client → Server | Client already has IP, requests other config options |

```python
DhcpMessageType.from_int(5)   # → DhcpMessageType.ACK
DhcpMessageType.from_int(99)  # → None  (unknown type, no exception)
```

---

## Troubleshooting Examples

### Log all DHCP activity to stdout

```python
import json
from lanscape import DhcpListener, DhcpListenerConfig

with DhcpListener(DhcpListenerConfig(), on_event=lambda e: print(e.model_dump_json(indent=2))):
    input("Press Enter to stop\n")
```

### Queue events for multi-threaded processing

```python
import queue
import threading
from lanscape import DhcpListener, DhcpListenerConfig

events: queue.Queue = queue.Queue()

def worker():
    while True:
        event = events.get()
        if event is None:
            break
        print(f"[{event.message_type.name}] {event.client_mac} → {event.effective_ip}")

t = threading.Thread(target=worker, daemon=True)
t.start()

with DhcpListener(DhcpListenerConfig(), on_event=events.put):
    input("Press Enter to stop\n")

events.put(None)
t.join()
```

### Watch for new devices on a specific subnet

```python
from lanscape import DhcpListener, DhcpListenerConfig, DhcpMessageType

config = DhcpListenerConfig(
    subnet_filter=["192.168.1.0/24"],
    message_types=[DhcpMessageType.DISCOVER],
    include_server_messages=False,
)

def on_discover(event):
    print(f"New device looking for lease: {event.client_mac}")
    print(f"  Hostname      : {event.hostname or '(not set)'}")
    print(f"  Vendor class  : {event.vendor_class or '(not set)'}")
    print(f"  Requested IP  : {event.requested_ip or '(any)'}")

with DhcpListener(config, on_event=on_discover):
    input("Press Enter to stop\n")
```

### Correlate with a running scan

```python
from lanscape import DhcpListener, DhcpListenerConfig, DhcpMessageType, ScanManager, ScanConfig

sm = ScanManager()
config = ScanConfig(subnet="192.168.1.0/24", port_list="small")
scan = sm.new_scan(config)

def on_dhcp(event):
    if event.message_type == DhcpMessageType.ACK and event.offered_ip:
        print(f"New lease granted: {event.offered_ip} → {event.client_mac}")

dhcp_cfg = DhcpListenerConfig(subnet_filter=["192.168.1.0/24"])
with DhcpListener(dhcp_cfg, on_event=on_dhcp):
    sm.wait_until_complete(scan.uid)

results = scan.results.to_results()
print(f"Scan complete — {len(results.devices)} devices found")
```

---

## Notes

- `DhcpListener` uses [scapy](https://scapy.net/)'s `AsyncSniffer` with a BPF filter `udp and (port 67 or port 68)`. scapy is bundled as a dependency of LANscape.
- The `on_event` callback runs on the sniffer thread. For non-trivial processing, dispatch to a `queue.Queue` to avoid blocking packet capture.
- On Windows, scapy requires [Npcap](https://npcap.com/) or WinPcap to be installed.
- On Linux, raw socket capture typically requires `CAP_NET_RAW` or running as root.
