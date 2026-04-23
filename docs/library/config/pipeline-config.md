# PipelineConfig

`lanscape.PipelineConfig`

The composable pipeline configuration model for building multi-stage scan workflows. Where [`ScanConfig`](scan-config.md) provides a monolithic configuration, `PipelineConfig` lets you define an explicit, ordered list of stages — mixing and repeating discovery and port-scan stages however you like.

> **Backward compatible:** You don't have to switch. `ScanConfig` still works and auto-converts via `.to_pipeline_config()` under the hood.

## Import

```python
from lanscape import PipelineConfig, StageConfig, StageType
```

## Constructor

```python
PipelineConfig(
    subnet: str,
    stages: List[StageConfig] = [],
    resilience: ResilienceConfig = ResilienceConfig(),
    hostname_config: HostnameConfig = HostnameConfig(),
)
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `subnet` | `str` | *required* | Target subnet in CIDR, range, or comma-separated format (IPv4 and/or IPv6) |
| `stages` | `List[StageConfig]` | `[]` | Ordered list of stages to execute. Each entry defines a stage type and its config. |
| `resilience` | [`ResilienceConfig`](#resilienceconfig) | `ResilienceConfig()` | Thread-pool retry and multiplier settings shared across all stages |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Default hostname resolution settings |

---

## StageConfig

`lanscape.StageConfig`

A single entry in the pipeline's stage list.

```python
from lanscape import StageConfig, StageType

stage = StageConfig(
    stage_type=StageType.ICMP_DISCOVERY,
    config={"ping_config": {"timeout": 2.0}},
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `stage_type` | [`StageType`](enums.md#stagetype) | *required* | Which stage to run |
| `config` | `Dict[str, Any]` | `{}` | Stage-specific configuration (deserialized into the appropriate model) |
| `auto` | `bool \| None` | `None` | Whether this stage was auto-recommended by the recommendation engine |
| `reason` | `str \| None` | `None` | Human-readable reason the stage was auto-recommended |

### `get_typed_config() -> ConfigBase`

Parse the raw `config` dict into the stage-specific Pydantic model (e.g. `ICMPDiscoveryStageConfig`).

---

## ResilienceConfig

`lanscape.ResilienceConfig`

Thread-pool resilience and retry settings shared across all stages in a pipeline.

```python
from lanscape import ResilienceConfig

resilience = ResilienceConfig(
    t_multiplier=1.5,
    failure_retry_cnt=3,
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `t_multiplier` | `float` | `1.0` | Global thread-count multiplier. Reduced automatically on failures. |
| `failure_retry_cnt` | `int` | `2` | Max retries per failed job |
| `failure_multiplier_decrease` | `float` | `0.25` | Percentage to reduce `t_multiplier` on failure (0.25 = 25%) |
| `failure_debounce_sec` | `float` | `5.0` | Minimum seconds between multiplier reductions |

---

## Stage Types

Seven stage types are available via [`StageType`](enums.md#stagetype):

| StageType | Category | Description | Config Model |
|-----------|----------|-------------|--------------|
| `ICMP_DISCOVERY` | IPv4 Discovery | ICMP echo requests (ping) | [`ICMPDiscoveryStageConfig`](#icmpdiscoverystageconfig) |
| `ARP_DISCOVERY` | IPv4 Discovery | Scapy ARP broadcast (IPv4 only, requires elevated privileges) | [`ARPDiscoveryStageConfig`](#arpdiscoverystageconfig) |
| `POKE_ARP_DISCOVERY` | IPv4 Discovery | TCP poke → ARP/NDP cache check | [`PokeARPDiscoveryStageConfig`](#pokearpdiscoverystageconfig) |
| `ICMP_ARP_DISCOVERY` | IPv4 Discovery | ICMP ping → ARP/NDP cache fallback | [`ICMPARPDiscoveryStageConfig`](#icmparpdiscoverystageconfig) |
| `IPV6_NDP_DISCOVERY` | IPv6 Discovery | Multicast NDP neighbor discovery | [`IPv6NDPDiscoveryStageConfig`](#ipv6ndpdiscoverystageconfig) |
| `IPV6_MDNS_DISCOVERY` | IPv6 Discovery | mDNS service browsing (requires `zeroconf`) | [`IPv6MDNSDiscoveryStageConfig`](#ipv6mdnsdiscoverystageconfig) |
| `PORT_SCAN` | Port Scan | TCP port scan with optional service identification | [`PortScanStageConfig`](#portscanstageconfig) |

---

## Stage Config Models

Each stage type has a dedicated Pydantic config model. Pass the model's fields as a dict in `StageConfig.config`.

### ICMPDiscoveryStageConfig

`lanscape.ICMPDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ping_config` | [`PingConfig`](sub-configs.md#pingconfig) | `PingConfig()` | ICMP ping settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `t_cnt` | `int` | `cpu_count() × 6` | Thread count for discovery workers |

### ARPDiscoveryStageConfig

`lanscape.ARPDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `arp_config` | [`ArpConfig`](sub-configs.md#arpconfig) | `ArpConfig()` | ARP scan settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `t_cnt` | `int` | `cpu_count() × 6` | Thread count for discovery workers |

### PokeARPDiscoveryStageConfig

`lanscape.PokeARPDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `poke_config` | [`PokeConfig`](sub-configs.md#pokeconfig) | `PokeConfig()` | TCP poke settings |
| `arp_cache_config` | [`ArpCacheConfig`](sub-configs.md#arpcacheconfig) | `ArpCacheConfig()` | ARP cache lookup settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `t_cnt` | `int` | `cpu_count() × 6` | Thread count for discovery workers |

### ICMPARPDiscoveryStageConfig

`lanscape.ICMPARPDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ping_config` | [`PingConfig`](sub-configs.md#pingconfig) | `PingConfig()` | ICMP ping settings |
| `arp_cache_config` | [`ArpCacheConfig`](sub-configs.md#arpcacheconfig) | `ArpCacheConfig()` | ARP cache lookup settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `t_cnt` | `int` | `cpu_count() × 6` | Thread count for discovery workers |

### IPv6NDPDiscoveryStageConfig

`lanscape.IPv6NDPDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `neighbor_table_config` | [`NeighborTableConfig`](sub-configs.md#neighbortableconfig) | `NeighborTableConfig()` | Background neighbor table refresh settings |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `t_cnt` | `int` | `cpu_count() × 4` | Thread count for discovery workers |
| `interface` | `str \| None` | `None` | Specific network interface to probe. Auto-detected if `None`. |

### IPv6MDNSDiscoveryStageConfig

`lanscape.IPv6MDNSDiscoveryStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | `float` | `5.0` | Seconds to listen for mDNS responses |
| `hostname_config` | [`HostnameConfig`](sub-configs.md#hostnameconfig) | `HostnameConfig()` | Hostname resolution settings |
| `interface` | `str \| None` | `None` | Specific network interface. Auto-detected if `None`. |

> **Requires `zeroconf`:** If the `zeroconf` package is not installed, this stage logs a warning and is skipped.

### PortScanStageConfig

`lanscape.PortScanStageConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port_list` | `str` | `"medium"` | Port list name to scan |
| `port_scan_config` | [`PortScanConfig`](sub-configs.md#portscanconfig) | `PortScanConfig()` | TCP connect scan settings |
| `service_scan_config` | [`ServiceScanConfig`](sub-configs.md#servicescanconfig) | `ServiceScanConfig()` | Service identification settings |
| `scan_services` | `bool` | `True` | Whether to identify services on open ports |
| `t_cnt_device` | `int` | `cpu_count()` | Thread count for the outer device pool |
| `t_cnt_port` | `int` | `cpu_count() × 4` | Thread count for the inner port pool (per device) |

> **Incremental scanning:** `PortScanStage` only processes devices that haven't been port-scanned yet. This means you can insert multiple `PORT_SCAN` stages in a pipeline — each one only scans devices discovered since the last port-scan stage.

---

## Subnet Size Limits

Each IPv4 enumeration stage has a `MAX_SUBNET_SIZE` class constant that caps how large a subnet it will accept. If a `PipelineConfig` is passed to `build_stages()` with a subnet that exceeds a stage's limit, a `ValueError` is raised before any IPs are allocated.

| Stage | `MAX_SUBNET_SIZE` |
|-------|-------------------|
| `ICMP_DISCOVERY` | 25,000 IPs |
| `ARP_DISCOVERY` | 25,000 IPs |
| `POKE_ARP_DISCOVERY` | 64,000 IPs |
| `ICMP_ARP_DISCOVERY` | 25,000 IPs |
| `IPV6_NDP_DISCOVERY` | No limit (passive, not IP-enumeration) |
| `IPV6_MDNS_DISCOVERY` | No limit (passive multicast) |
| `PORT_SCAN` | No limit (operates on discovered devices) |

---

## Utilities

### `get_stage_config_defaults() -> Dict[str, dict]`

Returns the default configuration dict for every stage type. Useful for pre-populating a UI or generating documentation.

```python
from lanscape.core.scan_config import get_stage_config_defaults

defaults = get_stage_config_defaults()
# {
#   "icmp_discovery": { "ping_config": {...}, "hostname_config": {...}, "t_cnt": 48 },
#   "port_scan": { "port_list": "medium", ... },
#   ...
# }
```

---

## Converting from ScanConfig

`ScanConfig` has a `.to_pipeline_config()` method that maps legacy fields to pipeline stages:

| ScanConfig field | Pipeline equivalent |
|------------------|---------------------|
| `lookup_type: [ICMP]` | `StageConfig(stage_type=StageType.ICMP_DISCOVERY, ...)` |
| `lookup_type: [ARP_LOOKUP]` | `StageConfig(stage_type=StageType.ARP_DISCOVERY, ...)` |
| `lookup_type: [POKE_THEN_ARP]` | `StageConfig(stage_type=StageType.POKE_ARP_DISCOVERY, ...)` |
| `lookup_type: [ICMP_THEN_ARP]` | `StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY, ...)` |
| `task_scan_ports: True` | `StageConfig(stage_type=StageType.PORT_SCAN, ...)` appended |
| Retry/threading fields | Mapped to `ResilienceConfig` |

```python
from lanscape import ScanConfig

legacy = ScanConfig(subnet="192.168.1.0/24", port_list="medium")
pipeline = legacy.to_pipeline_config()
# PipelineConfig with [ICMP_ARP_DISCOVERY, PORT_SCAN]
```

---

## Example: Basic PipelineConfig

```python
from lanscape import (
    ScanManager, PipelineConfig, StageConfig, StageType
)

sm = ScanManager()

config = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY),
        StageConfig(
            stage_type=StageType.PORT_SCAN,
            config={"port_list": "medium"},
        ),
    ],
)

scan = sm.new_scan(config)
sm.wait_until_complete(scan.uid)

for device in scan.results.to_results().devices:
    print(f"{device.ip} - {device.hostname} - Ports: {device.ports}")
```

## Example: Multi-Strategy Discovery

Run ICMP first for fast discovery, then ARP to catch devices that block ICMP, then port-scan:

```python
config = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_DISCOVERY),
        StageConfig(stage_type=StageType.ARP_DISCOVERY),
        StageConfig(
            stage_type=StageType.PORT_SCAN,
            config={"port_list": "large"},
        ),
    ],
)
```

## Example: Interleaved Discovery and Port Scanning

Discover with ICMP and immediately port-scan those devices, then run ARP to find more devices and port-scan the new ones:

```python
config = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY),
        StageConfig(
            stage_type=StageType.PORT_SCAN,
            config={"port_list": "small"},
        ),
        StageConfig(stage_type=StageType.ARP_DISCOVERY),
        StageConfig(
            stage_type=StageType.PORT_SCAN,
            config={"port_list": "small"},
        ),
    ],
)
```

> The second `PORT_SCAN` only processes devices found by the `ARP_DISCOVERY` stage — devices already scanned are skipped.

## Example: IPv6 Pipeline

```python
config = PipelineConfig(
    subnet="fd00::/120",
    stages=[
        StageConfig(stage_type=StageType.IPV6_NDP_DISCOVERY),
        StageConfig(stage_type=StageType.IPV6_MDNS_DISCOVERY),
        StageConfig(
            stage_type=StageType.PORT_SCAN,
            config={"port_list": "medium"},
        ),
    ],
)
```

## Example: Tracking Stage Progress

```python
import time
from lanscape import ScanManager, PipelineConfig, StageConfig, StageType

sm = ScanManager()
config = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY),
        StageConfig(stage_type=StageType.PORT_SCAN, config={"port_list": "small"}),
    ],
)

scan = sm.new_scan(config)

while scan.running:
    meta = scan.results.get_metadata()
    print(f"Overall: {meta.percent_complete:.0f}%")

    if meta.current_stage_index is not None:
        stage = meta.stages[meta.current_stage_index]
        print(f"  Stage {meta.current_stage_index + 1}/{len(meta.stages)}: "
              f"{stage.stage_name} — {stage.completed}/{stage.total}")

    for i, stage in enumerate(meta.stages):
        status = "✓" if stage.finished else ("▶" if i == meta.current_stage_index else "·")
        print(f"  {status} {stage.stage_name}: {stage.completed}/{stage.total}")

    time.sleep(1)
```
