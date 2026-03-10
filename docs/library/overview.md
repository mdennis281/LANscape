# LANscape Library Documentation

LANscape is a Python library for scanning your local network — discovering devices, testing ports, and identifying services.

These docs give more context on how to use LANscape as a Python library instead of using the high-level module.

## Installation

```bash
pip install lanscape
```

## Quick Start

```python
from lanscape import ScanManager, ScanConfig, net_tools

# Create a scan manager (singleton)
sm = ScanManager()

# Auto-detect your primary subnet (may return IPv4 or IPv6)
subnet = net_tools.smart_select_primary_subnet()

# Configure and run a scan
config = ScanConfig(subnet=subnet, port_list="medium")
scan = sm.new_scan(config)

# Wait for completion
sm.wait_until_complete(scan.uid)

# Get results
results = scan.results.to_results()
for device in results.devices:
    print(f"{device.ip} - {device.hostname} - Ports: {device.ports}")
```

> **IPv6 support:** LANscape natively supports IPv6 targets. Pass any IPv6 CIDR, range, or address as the `subnet` parameter and the entire scanning pipeline — discovery, port scanning, service detection, and hostname resolution — handles it automatically.

## Module Map

| Module | Description |
|--------|-------------|
| [`ScanManager`](scanner/scan-manager.md) | Singleton that creates, tracks, and terminates scans |
| [`SubnetScanner`](scanner/subnet-scanner.md) | The scan engine — runs device discovery and port scanning |
| [`ScannerResults`](scanner/scanner-results.md) | Result container with export helpers (`to_results()`, `to_summary()`, etc.) |
| [`ScanConfig`](config/scan-config.md) | Main scan configuration (subnet, ports, threads, sub-configs) |
| [Sub-Configs](config/sub-configs.md) | `PingConfig`, `ArpConfig`, `PokeConfig`, `ArpCacheConfig`, `PortScanConfig`, `ServiceScanConfig` |
| [`ScanType` / `ServiceScanStrategy`](config/enums.md) | Enumerations for scan modes and service detection strategies |
| [`PortManager`](port-manager.md) | CRUD operations for port lists |
| [Models](models/overview.md) | Pydantic models for devices and scan results |
| [`net_tools`](net-tools.md) | Network utility functions (subnet detection, ARP support check, hostname resolution) |
| [WebSocket Server](websocket-server.md) | Real-time WebSocket API, HTTP discovery endpoint, mDNS, and CLI arguments |

## Architecture Overview

```
ScanManager (singleton)
  └─ SubnetScanner (one per scan)
       ├─ Device Discovery  — find alive hosts via ICMP / ARP / Poke
       │     (IPv6: ARP steps skipped, ICMP & Poke use AF_INET6)
       ├─ Port Scanning     — test configured ports on each alive device
       ├─ Service Detection  — identify what's running on open ports
       └─ ScannerResults
            ├─ to_results()   → ScanResults  (full device list + metadata)
            ├─ to_summary()   → ScanSummary  (ports & services found)
            └─ get_metadata() → ScanMetadata (progress & status)
```

## Default Presets

LANscape ships with three built-in presets available via `DEFAULT_CONFIGS`:

| Preset | Port List | Scan Strategy | Thread Profile | Notes |
|--------|-----------|---------------|----------------|-------|
| `balanced` | `medium` | `ICMP_THEN_ARP` | CPU defaults | Good all-around choice |
| `accurate` | `large` | `ICMP_THEN_ARP` + `ARP_LOOKUP` | Conservative (5/64/64) | Slower but thorough |
| `fast` | `small` | `POKE_THEN_ARP` | Aggressive (20/256/512) | Quick overview |

```python
from lanscape.core.scan_config import DEFAULT_CONFIGS

config = DEFAULT_CONFIGS['fast']
config.subnet = "192.168.1.0/24"
```

## Full Example

```python
from lanscape import ScanManager, ScanConfig, ScanType, PokeConfig, net_tools

sm = ScanManager()

config = ScanConfig(
    subnet=net_tools.smart_select_primary_subnet(),
    port_list="medium",
    lookup_type=[ScanType.POKE_THEN_ARP],
    poke_config=PokeConfig(timeout=0.25, attempts=4),
)

try:
    scan = sm.new_scan(config)
    scan.debug_active_scan()  # Live progress in terminal
except KeyboardInterrupt:
    scan.terminate()

# Export results
results = scan.results.to_results()
for device in results.devices:
    services = ", ".join(device.services.keys()) or "none"
    print(f"{device.ip:16s} {device.hostname or '':20s} ports={device.ports}  services={services}")

# JSON export
print(results.model_dump_json(indent=2))
```

## IPv6 Scanning Example

Scan an IPv6 subnet exactly the same way as IPv4 — just pass an IPv6 CIDR, range, or address list:

```python
from lanscape import ScanManager, ScanConfig, ScanType

sm = ScanManager()

# CIDR notation
config = ScanConfig(subnet="fd00::/120", port_list="medium")
scan = sm.new_scan(config)
sm.wait_until_complete(scan.uid)

for device in scan.results.to_results().devices:
    print(f"{device.ip} - {device.hostname} - Ports: {device.ports}")
```

You can also mix IPv4 and IPv6 in comma-separated lists:

```python
config = ScanConfig(
    subnet="192.168.1.1,fd00::1,fd00::2",
    port_list="small"
)
```

### IPv6 Behavior Notes

| Feature | IPv6 Behavior |
|---------|---------------|
| ICMP ping | Uses `ping6` (Linux/macOS) or `ping -6` (Windows) |
| ARP discovery | Skipped — ARP is IPv4-only. IPv6 uses NDP (Neighbor Discovery Protocol). |
| TCP poke | Uses `AF_INET6` sockets |
| Port scanning | Uses `AF_INET6` sockets |
| MAC resolution | Falls through to NDP neighbor cache (Scapy ARP skipped) |
| Hostname (mDNS) | Queries `ip6.arpa` PTR records via `ff02::fb` multicast |
| Hostname (NetBIOS) | Skipped — NetBIOS is IPv4-only |
| Result sorting | IPv4 devices sort before IPv6 devices |
