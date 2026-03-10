# Sub-Configs

Protocol-specific configuration models used by [`ScanConfig`](scan-config.md). All inherit from `ConfigBase` (a Pydantic `BaseModel` subclass) which provides shared `from_dict()` and `to_dict()` methods.

---

## PingConfig

`lanscape.PingConfig`

Controls ICMP ping behavior for device discovery when using `ScanType.ICMP` or `ScanType.ICMP_THEN_ARP`.

```python
from lanscape import PingConfig

cfg = PingConfig(attempts=3, ping_count=2, timeout=1.5, retry_delay=0.5)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `attempts` | `int` | `2` | Number of ping attempts per device before declaring it unresponsive |
| `ping_count` | `int` | `1` | Number of ICMP echo packets per attempt (`-c` flag equivalent) |
| `timeout` | `float` | `1.0` | Timeout in seconds for each ping attempt |
| `retry_delay` | `float` | `0.25` | Delay in seconds between retry attempts |

---

## ArpConfig

`lanscape.ArpConfig`

Controls ARP request behavior for device discovery when using `ScanType.ARP_LOOKUP`.

```python
from lanscape import ArpConfig

cfg = ArpConfig(attempts=3, timeout=2.5)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `attempts` | `int` | `1` | Number of ARP request attempts |
| `timeout` | `float` | `2.0` | Timeout in seconds for each ARP request |

> **Note:** ARP scanning requires elevated privileges and only works within the local network segment. Use `net_tools.is_arp_supported()` to check availability. ARP is IPv4-only — for IPv6 targets, this discovery method is automatically skipped.

---

## ArpCacheConfig

`lanscape.ArpCacheConfig`

Controls ARP cache lookup behavior. Used as a fallback after other alive-check methods to retrieve MAC addresses from the OS ARP cache.

```python
from lanscape import ArpCacheConfig

cfg = ArpCacheConfig(attempts=2, wait_before=0.3)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `attempts` | `int` | `1` | Number of ARP cache lookup attempts |
| `wait_before` | `float` | `0.2` | Seconds to wait before checking the cache (allows ARP entries to populate) |

> **Note:** ARP cache lookups are IPv4-only. For IPv6 targets, this step is automatically skipped. IPv6 MAC resolution uses the system’s NDP (Neighbor Discovery Protocol) neighbor cache instead.

---

## PokeConfig

`lanscape.PokeConfig`

Controls TCP "poke" behavior. A poke sends a TCP packet to a device to trigger an ARP response. Used by `ScanType.POKE_THEN_ARP`.

```python
from lanscape import PokeConfig

cfg = PokeConfig(attempts=4, timeout=0.25)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `attempts` | `int` | `1` | Number of poke attempts |
| `timeout` | `float` | `2.0` | Timeout in seconds for each poke |

> **How it works:** The poke doesn't expect a TCP response — it's just enough traffic to populate the local ARP cache (or NDP neighbor cache for IPv6), which is then checked for the device's MAC. For IPv6 targets, `AF_INET6` sockets are used automatically.

---

## PortScanConfig

`lanscape.PortScanConfig`

Controls per-port TCP connect scanning behavior.

```python
from lanscape import PortScanConfig

cfg = PortScanConfig(timeout=2.0, retries=1, retry_delay=0.2)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | `float` | `1.0` | Timeout in seconds for each TCP connect attempt |
| `retries` | `int` | `0` | Number of retries per port (0 = single attempt only) |
| `retry_delay` | `float` | `0.1` | Delay in seconds between retries |

> A timeout enforcer wraps each port test at `timeout × (retries + 1) × 1.5` seconds to prevent hung connections.

---

## ServiceScanConfig

`lanscape.ServiceScanConfig`

Controls service identification on open ports.

```python
from lanscape import ServiceScanConfig, ServiceScanStrategy

cfg = ServiceScanConfig(
    timeout=8.0,
    lookup_type=ServiceScanStrategy.AGGRESSIVE,
    max_concurrent_probes=5
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | `float` | `5.0` | Timeout in seconds for each service probe |
| `lookup_type` | [`ServiceScanStrategy`](enums.md#servicescanstrategy) | `BASIC` | Probe strategy controlling how many probes are sent |
| `max_concurrent_probes` | `int` | `10` | Maximum probes to run in parallel for a single port |

### Service Scan Strategies

| Strategy | Description |
|----------|-------------|
| `LAZY` | A few common probes to quickly identify common services |
| `BASIC` | Common probes plus probes correlated to the specific port number |
| `AGGRESSIVE` | All known probes in parallel for maximum identification coverage |
