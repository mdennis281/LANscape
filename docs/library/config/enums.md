# Enums

Enumeration types used across the LANscape configuration and model layers.

---

## ScanType

`lanscape.ScanType`

Determines how the scanner checks whether a device is alive during the discovery phase.

```python
from lanscape import ScanType
```

| Value | String | Description |
|-------|--------|-------------|
| `ScanType.ICMP` | `"ICMP"` | Standard ICMP echo request (ping). Most universally supported but may be blocked by firewalls. |
| `ScanType.ARP_LOOKUP` | `"ARP_LOOKUP"` | Active ARP request via scapy. Only works on the local network segment. Requires elevated privileges. |
| `ScanType.POKE_THEN_ARP` | `"POKE_THEN_ARP"` | Sends a TCP packet to trigger ARP cache population, then checks the ARP cache. Good fallback when ARP scanning isn't available. |
| `ScanType.ICMP_THEN_ARP` | `"ICMP_THEN_ARP"` | Tries ICMP first, falls back to ARP cache lookup on failure. Best balance of coverage. **Default strategy.** |

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
