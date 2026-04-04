# Scan Pipeline

LANscape's scan pipeline architecture lets you compose scan workflows from independent, reusable stages. Instead of a monolithic scan loop, each phase — ICMP discovery, ARP discovery, port scanning, etc. — is a self-contained stage that reads from and writes to a shared context.

## Architecture

```
PipelineConfig
  └─ build_stages()  →  List[ScanStageMixin]
                              │
ScanPipeline.execute(context)
  ├─ Stage 1: ICMP Discovery    ──▶ context.add_device(...)
  ├─ Stage 2: ARP Discovery     ──▶ context.add_device(...)
  ├─ Stage 3: Port Scan          ──▶ context.mark_port_scanned(...)
  └─ ...
                              │
ScanContext (shared state)
  ├─ devices          — all discovered devices (deduplicated by IP)
  ├─ errors/warnings  — scan-level diagnostics
  └─ port_scanned_ips — tracks which devices have been port-scanned
```

## Core Components

| Component | Module | Description |
|-----------|--------|-------------|
| [`PipelineConfig`](../config/pipeline-config.md) | `lanscape.PipelineConfig` | Declarative pipeline definition — subnet, stage list, resilience settings |
| `ScanStageMixin` | `lanscape.ScanStageMixin` | Abstract base class for all stages |
| `ScanContext` | `lanscape.ScanContext` | Thread-safe shared state passed between stages |
| `ScanPipeline` | `lanscape.ScanPipeline` | Sequential stage executor |
| `build_stages()` | `lanscape.build_stages` | Factory that builds stage instances from a `PipelineConfig` |

---

## ScanStageMixin

`lanscape.ScanStageMixin`

Abstract base class for all scan stages. Provides standardised progress tracking (total, completed, finished) and a thread-safe `increment()` helper.

### Class Attributes

Subclasses must define:

| Attribute | Type | Description |
|-----------|------|-------------|
| `stage_type` | [`StageType`](../config/enums.md#stagetype) | Identifies the stage kind |
| `stage_name` | `str` | Human-readable name (e.g. `"ICMP Discovery"`) |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `total` | `int` | Total work items (thread-safe setter) |
| `completed` | `int` | Completed work items |
| `finished` | `bool` | Whether the stage has finished |
| `running` | `bool` | Whether the stage is currently executing |

### Methods

| Method | Description |
|--------|-------------|
| `increment()` | Thread-safe increment of `completed` |
| `stage_progress() -> StageProgress` | Return an immutable progress snapshot |
| `run(context)` | Entry-point called by `ScanPipeline` — wraps `execute()` with bookkeeping |
| `execute(context)` | **Abstract.** Implement your stage logic here. |
| `terminate()` | Request graceful stop by setting `running = False` |

### Lifecycle

```
ScanPipeline calls stage.run(context)
  ├─ sets running = True, finished = False
  ├─ calls stage.execute(context)      ◄── your code
  └─ sets running = False, finished = True
```

---

## ScanContext

`lanscape.ScanContext`

Thread-safe container for data shared across stages within a single pipeline execution.

### Constructor

```python
ScanContext(subnet: str)
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `subnet` | `str` | Target subnet string |
| `start_time` | `float` | Unix timestamp when the context was created |
| `devices` | `List[Device]` | Snapshot of all discovered devices |
| `devices_alive` | `int` | Count of discovered devices |
| `errors` | `List[ScanErrorInfo]` | Scan-level errors |
| `warnings` | `List[ScanWarningInfo]` | Scan-level warnings |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `add_device(device)` | `bool` | Add a device (deduplicated by IP). Returns `True` if added. |
| `get_unscanned_devices()` | `List[Device]` | Devices not yet port-scanned |
| `mark_port_scanned(ip)` | `None` | Mark an IP as port-scanned |

---

## ScanPipeline

`lanscape.ScanPipeline`

Sequential executor for an ordered list of stages.

### Constructor

```python
ScanPipeline(stages: List[ScanStageMixin])
```

### Methods

| Method | Description |
|--------|-------------|
| `execute(context)` | Run each stage in order, passing the shared context |
| `terminate()` | Terminate the current stage and skip remaining stages |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `current_stage` | `ScanStageMixin \| None` | The currently executing stage |
| `current_stage_index` | `int \| None` | Index of the current stage |
| `get_stage_progress()` | `List[StageProgress]` | Progress snapshots for all stages |

---

## Built-in Stages

### IPv4 Discovery Stages

| Class | StageType | Description |
|-------|-----------|-------------|
| `ICMPDiscoveryStage` | `ICMP_DISCOVERY` | ICMP echo requests (ping) |
| `ARPDiscoveryStage` | `ARP_DISCOVERY` | Scapy ARP broadcast (IPv4 only) |
| `PokeARPDiscoveryStage` | `POKE_ARP_DISCOVERY` | TCP poke → ARP/NDP cache lookup |
| `ICMPARPDiscoveryStage` | `ICMP_ARP_DISCOVERY` | ICMP ping → ARP/NDP cache fallback |

### IPv6 Discovery Stages

| Class | StageType | Description |
|-------|-----------|-------------|
| `IPv6NDPDiscoveryStage` | `IPV6_NDP_DISCOVERY` | Multicast NDP — pings `ff02::1` then harvests neighbor table |
| `IPv6MDNSDiscoveryStage` | `IPV6_MDNS_DISCOVERY` | mDNS service browsing via `zeroconf` |

### Port Scan Stage

| Class | StageType | Description |
|-------|-----------|-------------|
| `PortScanStage` | `PORT_SCAN` | TCP connect scan with optional service identification |

All built-in stage classes are importable from the top-level package:

```python
from lanscape import (
    ICMPDiscoveryStage, ARPDiscoveryStage,
    PokeARPDiscoveryStage, ICMPARPDiscoveryStage,
    IPv6NDPDiscoveryStage, IPv6MDNSDiscoveryStage,
    PortScanStage,
)
```

---

## Creating Custom Stages

Subclass `ScanStageMixin` to build your own stage. The minimum requirements are:

1. Set `stage_type` and `stage_name` class attributes
2. Implement `execute(context: ScanContext)`
3. Use `self.total`, `self.increment()`, and `self.running` for progress tracking

```python
from lanscape import ScanStageMixin, ScanContext, StageType


class BannerGrabStage(ScanStageMixin):
    """Custom stage: grab banners from open ports on discovered devices."""

    stage_type = StageType.PORT_SCAN  # reuse an existing type, or define your own
    stage_name = "Banner Grab"

    def __init__(self, ports: list[int], timeout: float = 2.0):
        super().__init__()
        self.ports = ports
        self.timeout = timeout

    def execute(self, context: ScanContext) -> None:
        devices = context.get_unscanned_devices()
        self.total = len(devices) * len(self.ports)

        for device in devices:
            if not self.running:
                break
            for port in self.ports:
                if not self.running:
                    break
                # ... your banner grab logic ...
                self.increment()
            context.mark_port_scanned(device.ip)
```

### Using a Custom Stage in a Pipeline

```python
from lanscape import ScanManager, ScanPipeline, ScanContext, build_stages, PipelineConfig, StageConfig, StageType

sm = ScanManager()

# Build the standard stages from config
pipeline_cfg = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY),
    ],
)
stages = build_stages(pipeline_cfg)

# Append your custom stage
stages.append(BannerGrabStage(ports=[22, 80, 443]))

# Execute manually via ScanPipeline + ScanContext
context = ScanContext(subnet="192.168.1.0/24")
pipeline = ScanPipeline(stages)
pipeline.execute(context)

# Access results from context
for device in context.devices:
    print(f"{device.ip} — alive={device.alive}")
```

---

## Stage Progress Model

`lanscape.StageProgress`

Immutable snapshot of a single stage's progress. Available in `ScanMetadata.stages`.

| Field | Type | Description |
|-------|------|-------------|
| `stage_name` | `str` | Human-readable stage name |
| `stage_type` | [`StageType`](../config/enums.md#stagetype) | Stage type identifier |
| `total` | `int` | Total work items |
| `completed` | `int` | Completed work items |
| `finished` | `bool` | Whether the stage has finished |

```python
meta = scan.results.get_metadata()
for stage in meta.stages:
    pct = (stage.completed / stage.total * 100) if stage.total else 0
    print(f"{stage.stage_name}: {pct:.0f}% ({'done' if stage.finished else 'running'})")
```
