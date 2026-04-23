# ScanConfig

`lanscape.ScanConfig`

The main Pydantic configuration model for a network scan. Controls every aspect of the scan: target subnet, port list, thread counts, device-discovery strategy, retry behavior, and per-protocol tuning via sub-configs.

## Import

```python
from lanscape import ScanConfig
```

## Constructor

```python
ScanConfig(
    subnet: str,
    port_list: str,
    t_multiplier: float = 1.0,
    t_cnt_port_scan: int = os.cpu_count(),
    t_cnt_port_test: int = os.cpu_count() * 4,
    t_cnt_isalive: int = os.cpu_count() * 6,
    task_scan_ports: bool = True,
    task_scan_port_services: bool = True,
    lookup_type: List[ScanType] = [ScanType.ICMP_THEN_ARP],
    failure_retry_cnt: int = 2,
    failure_multiplier_decrease: float = 0.25,
    failure_debounce_sec: float = 5.0,
    ping_config: PingConfig = PingConfig(),
    arp_config: ArpConfig = ArpConfig(),
    poke_config: PokeConfig = PokeConfig(),
    arp_cache_config: ArpCacheConfig = ArpCacheConfig(),
    neighbor_table_config: NeighborTableConfig = NeighborTableConfig(),
    port_scan_config: PortScanConfig = PortScanConfig(),
    service_scan_config: ServiceScanConfig = ServiceScanConfig(),
    hostname_config: HostnameConfig = HostnameConfig(),
)
```

## Fields

### Target

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subnet` | `str` | *required* | Target subnet in CIDR, range, or comma-separated format. Supports both IPv4 and IPv6 (e.g., `"192.168.1.0/24"`, `"fd00::/120"`, `"10.0.0.1-10.0.0.50"`, `"fd00::1-fd00::ff"`, `"1.1.1.1,fd00::1"`) |
| `port_list` | `str` | *required* | Name of the port list to use (e.g., `"small"`, `"medium"`, `"large"`). Must exist in `PortManager`. |

### Threading

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `t_multiplier` | `float` | `1.0` | Global multiplier applied to all thread counts via `t_cnt()`. Reduced automatically on failures. |
| `t_cnt_port_scan` | `int` | `cpu_count()` | Base thread count for the outer port-scan pool (one device per thread) |
| `t_cnt_port_test` | `int` | `cpu_count() * 4` | Base thread count for the inner port-test pool (one port per thread, per device) |
| `t_cnt_isalive` | `int` | `cpu_count() * 6` | Base thread count for device discovery (is-alive checks) |

> **Effective thread count** = `int(t_cnt_<key> * t_multiplier)`. Call `config.t_cnt("isalive")` to get the computed value.

### Tasks

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `task_scan_ports` | `bool` | `True` | Whether to scan ports on alive devices |
| `task_scan_port_services` | `bool` | `True` | Whether to identify services on open ports. Only runs if `task_scan_ports` is also `True`. |

### Device Discovery Strategy

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `lookup_type` | `List[ScanType]` | `[ScanType.ICMP_THEN_ARP]` | Ordered list of strategies to determine if a device is alive. See [`ScanType`](enums.md#scantype). |

### Retry & Resilience

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_retry_cnt` | `int` | `2` | Max retries per failed job before it's marked as permanently failed |
| `failure_multiplier_decrease` | `float` | `0.25` | Percentage to reduce `t_multiplier` on failure (0.25 = 25% reduction) |
| `failure_debounce_sec` | `float` | `5.0` | Minimum seconds between multiplier reductions to prevent rapid over-correction |

### Sub-Configs

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ping_config` | [`PingConfig`](sub-configs.md#pingconfig) | `PingConfig()` | ICMP ping settings |
| `arp_config` | [`ArpConfig`](sub-configs.md#arpconfig) | `ArpConfig()` | ARP scan settings |
| `poke_config` | [`PokeConfig`](sub-configs.md#pokeconfig) | `PokeConfig()` | TCP poke settings |
| `arp_cache_config` | [`ArpCacheConfig`](sub-configs.md#arpcacheconfig) | `ArpCacheConfig()` | ARP cache lookup settings |
| `neighbor_table_config` | [`NeighborTableConfig`](sub-configs.md#neighbortableconfig) | `NeighborTableConfig()` | Background neighbor table refresh settings (IPv6) |
| `port_scan_config` | [`PortScanConfig`](sub-configs.md#portscanconfig) | `PortScanConfig()` | Port scanning settings |
| `service_scan_config` | [`ServiceScanConfig`](sub-configs.md#servicescanconfig) | `ServiceScanConfig()` | Service identification settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution retry settings |

## Methods

### `t_cnt(thread_id: str) -> int`

Calculate the effective thread count for a specific operation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `thread_id` | `str` | One of `"port_scan"`, `"port_test"`, or `"isalive"` |

**Returns:** `int` — `floor(t_cnt_{thread_id} × t_multiplier)`.

---

### `get_ports() -> List[int]`

Resolve the `port_list` name into actual port numbers using `PortManager`.

**Returns:** `List[int]` — sorted list of port numbers.

**Raises:** `ValueError` if the port list doesn't exist.

---

### `parse_subnet() -> List[IPv4Address | IPv6Address]`

Parse the `subnet` string into individual IP addresses. Supports IPv4 and IPv6 CIDR notation, ranges, and comma-separated mixed lists.

**Returns:** `List[IPv4Address | IPv6Address]` — every IP address in the target range.

---

### `from_dict(data: dict) -> ScanConfig` *(classmethod)*

Create a `ScanConfig` from a dictionary. Uses Pydantic's `model_validate()`. Inherited from `ConfigBase`.

---

### `to_dict() -> dict`

Serialize the config to a JSON-safe dictionary. Overrides the `ConfigBase` default to use `model_dump(mode="json")` for JSON-safe output (e.g., enum values serialized as strings).

---

### `to_pipeline_config() -> PipelineConfig`

Convert this `ScanConfig` into a [`PipelineConfig`](pipeline-config.md). Each `lookup_type` entry maps to a discovery stage, and `task_scan_ports` appends a port-scan stage. Thread counts and retry settings are carried over to the pipeline's `ResilienceConfig`.

This conversion happens automatically when you pass a `ScanConfig` to `ScanManager.new_scan()` — you only need to call it explicitly if building a pipeline manually.

```python
config = ScanConfig(subnet="192.168.1.0/24", port_list="medium")
pipeline = config.to_pipeline_config()
# PipelineConfig with stages: [ICMP_ARP_DISCOVERY, PORT_SCAN]
```

> **See also:** [`PipelineConfig`](pipeline-config.md) for the composable alternative that lets you define custom stage sequences directly.

## Default Presets

Three presets are available in `lanscape.core.scan_config.DEFAULT_CONFIGS`:

```python
from lanscape.core.scan_config import DEFAULT_CONFIGS

config = DEFAULT_CONFIGS['balanced']
config.subnet = "192.168.1.0/24"
```

| Preset | `port_list` | `lookup_type` | `t_cnt_port_scan` | `t_cnt_port_test` | `t_cnt_isalive` | `hostname_config` |
|--------|-------------|---------------|--------------------|--------------------|-----------------|--------------------|
| `balanced` | `medium` | `ICMP_THEN_ARP` | cpu_count | cpu×4 | cpu×6 | retries=1, delay=1.5s |
| `accurate` | `large` | `ICMP_THEN_ARP`, `ARP_LOOKUP` | 5 | 64 | 64 | retries=2, delay=2.0s |
| `fast` | `small` | `POKE_THEN_ARP` | 20 | 256 | 512 | retries=0 (disabled) |

### `get_default_configs_with_arp_fallback(arp_supported: bool) -> Dict[str, dict]`

Returns the default presets as dicts, substituting `ARP_LOOKUP` with `POKE_THEN_ARP` when ARP is not supported on the host.

| Parameter | Type | Description |
|-----------|------|-------------|
| `arp_supported` | `bool` | Whether active ARP scanning is available |

## Example: Custom Config

```python
from lanscape import (
    ScanConfig, ScanType,
    PingConfig, PokeConfig, PortScanConfig, ServiceScanConfig,
    ServiceScanStrategy, HostnameConfig
)

config = ScanConfig(
    subnet="192.168.1.0/24",
    port_list="medium",
    t_multiplier=1.5,
    lookup_type=[ScanType.POKE_THEN_ARP],
    task_scan_ports=True,
    task_scan_port_services=True,
    poke_config=PokeConfig(timeout=0.25, attempts=4),
    port_scan_config=PortScanConfig(timeout=2.0, retries=1, retry_delay=0.2),
    service_scan_config=ServiceScanConfig(
        timeout=8.0,
        lookup_type=ServiceScanStrategy.AGGRESSIVE,
        max_concurrent_probes=5
    ),
)
```

## Example: IPv6 Config

```python
from lanscape import ScanConfig, ScanType

# Scan an IPv6 subnet
config = ScanConfig(
    subnet="fd00::/120",
    port_list="medium",
    lookup_type=[ScanType.ICMP_THEN_ARP],  # ARP cache step auto-skipped for IPv6
)

# Mixed IPv4 + IPv6 comma-separated targets
config = ScanConfig(
    subnet="192.168.1.1,192.168.1.2,fd00::1,fd00::2",
    port_list="small",
)
```

> **IPv6 note:** ARP-based discovery steps (`ARP_LOOKUP`, ARP cache lookups) are automatically skipped for IPv6 targets since ARP is an IPv4-only protocol. IPv6 MAC resolution uses the system’s NDP (Neighbor Discovery Protocol) cache instead.
