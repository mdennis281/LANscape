# Enums

Enumeration types used across the LANscape configuration and model layers.

---

## StageType

`lanscape.StageType`

Identifies each composable scan stage in the [pipeline architecture](../scanner/scan-pipeline.md). Used by [`StageConfig`](pipeline-config.md#stageconfig) and [`StageProgress`](../models/overview.md#stageprogress).

```python
from lanscape import StageType
```

| Value | String | Description |
|-------|--------|-------------|
| `StageType.ICMP_DISCOVERY` | `"icmp_discovery"` | ICMP echo request discovery |
| `StageType.ARP_DISCOVERY` | `"arp_discovery"` | Scapy ARP broadcast (IPv4 only) |
| `StageType.POKE_ARP_DISCOVERY` | `"poke_arp_discovery"` | TCP poke → ARP/NDP cache lookup |
| `StageType.ICMP_ARP_DISCOVERY` | `"icmp_arp_discovery"` | ICMP ping → ARP/NDP cache fallback |
| `StageType.IPV6_NDP_DISCOVERY` | `"ipv6_ndp_discovery"` | Multicast NDP neighbor discovery |
| `StageType.IPV6_MDNS_DISCOVERY` | `"ipv6_mdns_discovery"` | mDNS service browsing |
| `StageType.PORT_SCAN` | `"port_scan"` | TCP port scan with service identification |

---

## WarningCategory

`lanscape.WarningCategory`

Categorizes scan warnings for grouping in the UI. Used by [`ScanWarningInfo`](../models/overview.md#scanwarninginfo).

```python
from lanscape import WarningCategory
```

| Value | String | Description |
|-------|--------|-------------|
| `WarningCategory.CONCURRENCY` | `"concurrency"` | Thread multiplier was reduced due to job failures |
| `WarningCategory.STAGE_SKIP` | `"stage_skip"` | A pipeline stage was skipped by its guard |
| `WarningCategory.CAPABILITY` | `"capability"` | A feature is degraded (missing dependency, permission fallback) |
| `WarningCategory.RESILIENCE` | `"resilience"` | A job failed permanently or a subsystem refresh failed |

---

## ScanType

`lanscape.ScanType`

Determines how the scanner checks whether a device is alive during the discovery phase.

```python
from lanscape import ScanType
```

| Value | String | Description |
|-------|--------|-------------|
| `ScanType.ICMP` | `"ICMP"` | Standard ICMP echo request (ping). Works for both IPv4 and IPv6 (`ping6` on Linux/macOS). Most universally supported but may be blocked by firewalls. |
| `ScanType.ARP_LOOKUP` | `"ARP_LOOKUP"` | Active ARP request via scapy. Only works on the local network segment. Requires elevated privileges. **IPv4 only** — automatically skipped for IPv6 targets. |
| `ScanType.POKE_THEN_ARP` | `"POKE_THEN_ARP"` | Sends a TCP packet to trigger ARP/NDP cache population, then checks the appropriate cache (ARP for IPv4, NDP neighbor cache for IPv6). Uses `AF_INET6` sockets for IPv6 targets. Good fallback when ARP/NDP scanning isn't available. |
| `ScanType.ICMP_THEN_ARP` | `"ICMP_THEN_ARP"` | Tries ICMP first, falls back to a cache-based lookup on failure (ARP cache for IPv4, NDP neighbor cache for IPv6). Best balance of coverage. **Default strategy.** |

### Multiple Strategies

`ScanConfig.lookup_type` accepts a list — strategies are tried in order:

```python
config = ScanConfig(
    subnet="192.168.1.0/24",
    port_list="medium",
    lookup_type=[ScanType.ICMP_THEN_ARP, ScanType.ARP_LOOKUP]
)
```

---

## ServiceScanStrategy

`lanscape.ServiceScanStrategy`

Controls the aggressiveness of service identification on open ports.

```python
from lanscape import ServiceScanStrategy
```

| Value | String | Description |
|-------|--------|-------------|
| `ServiceScanStrategy.LAZY` | `"LAZY"` | A few common probes for quick identification |
| `ServiceScanStrategy.BASIC` | `"BASIC"` | Common probes plus port-correlated probes. **Default.** |
| `ServiceScanStrategy.AGGRESSIVE` | `"AGGRESSIVE"` | All known probes sent in parallel for maximum coverage |

---

## DeviceStage

`lanscape.DeviceStage`

Tracks the scan progress of an individual device.

```python
from lanscape import DeviceStage
```

| Value | String | Description |
|-------|--------|-------------|
| `DeviceStage.FOUND` | `"found"` | Device was detected as alive |
| `DeviceStage.SCANNING` | `"scanning"` | Ports are currently being tested |
| `DeviceStage.COMPLETE` | `"complete"` | Port scanning finished |

---

## ScanStage

`lanscape.ScanStage`

Tracks the overall scan lifecycle.

```python
from lanscape import ScanStage
```

| Value | String | Description |
|-------|--------|-------------|
| `ScanStage.INSTANTIATED` | `"instantiated"` | Scanner created, not yet started |
| `ScanStage.SCANNING_DEVICES` | `"scanning devices"` | Device discovery phase |
| `ScanStage.TESTING_PORTS` | `"testing ports"` | Port scanning phase |
| `ScanStage.COMPLETE` | `"complete"` | Scan finished successfully |
| `ScanStage.TERMINATING` | `"terminating"` | Termination requested |
| `ScanStage.TERMINATED` | `"terminated"` | Scan terminated |
