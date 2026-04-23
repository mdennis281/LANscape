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
| `ScanPipeline` | `lanscape.ScanPipeline` | Sequential stage executor with automatic stage guards |
| `StageEvalContext` | `lanscape.StageEvalContext` | Environment context used by stage guards to decide whether to run or skip |
| `build_stages()` | `lanscape.build_stages` | Factory that builds stage instances from a `PipelineConfig` |

---

## StageEvalContext

`lanscape.StageEvalContext`

A Pydantic model that captures environment facts about the target subnet. The pipeline passes this to each stage's `can_execute()` guard so stages can decide whether they apply.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `subnet` | `str` | Target subnet string |
| `is_ipv6` | `bool` | Whether the target subnet is IPv6 |
| `is_local` | `bool` | Whether the target subnet overlaps a local interface |
| `matching_interface` | `str \| None` | Name of the overlapping local interface (or `None`) |
| `arp_supported` | `bool` | Whether the system supports ARP |
| `os_platform` | `str` | Normalised OS: `"windows"`, `"linux"`, or `"darwin"` |

### Factory

```python
StageEvalContext.build(subnet: str, arp_supported: bool = True) -> StageEvalContext
```

Probes the local system and returns a fully populated context. This is the recommended way to create one:

```python
from lanscape import StageEvalContext

ctx = StageEvalContext.build("192.168.1.0/24")
print(ctx.is_ipv6)    # False
print(ctx.is_local)   # True
print(ctx.os_platform) # "windows"
```

You can also construct one manually for testing or non-standard setups:

```python
ctx = StageEvalContext(
    subnet="fd00::/64",
    is_ipv6=True,
    is_local=True,
    matching_interface="eth0",
    arp_supported=False,
    os_platform="linux",
)
```

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
| `can_execute(eval_ctx) -> str \| None` | Return `None` to allow execution, or a reason string to skip. Default: always allows. |
| `mark_skipped(reason)` | Mark the stage as skipped without executing it |
| `terminate()` | Request graceful stop by setting `running = False` |

### Lifecycle

```
ScanPipeline calls stage.can_execute(eval_ctx)
  ├─ returns None      → stage.run(context)
  │                        ├─ sets running = True, finished = False
  │                        ├─ calls stage.execute(context)      ◄── your code
  │                        └─ sets running = False, finished = True
  └─ returns reason    → stage.mark_skipped(reason)
                           └─ sets finished = True, skipped = True
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
| `devices` | `List[Device]` | Thread-safe snapshot of all discovered devices |
| `devices_alive` | `int` | Count of discovered devices |
| `errors` | `List[ScanErrorInfo]` | Scan-level errors |
| `warnings` | `List[ScanWarningInfo]` | Scan-level warnings |
| `current_stage_index` | `int \| None` | Index of the currently executing stage (set by `ScanPipeline`) |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `add_device(device)` | `bool` | Add a device (deduplicated by IP). Returns `True` if added, `False` if duplicate. If the stage index is set, it's recorded on the device. |
| `get_unscanned_devices()` | `List[Device]` | Devices not yet port-scanned |
| `get_scanned_ports(ip)` | `Set[int]` | Returns the set of port numbers already tested for the given IP |
| `mark_port_scanned(ip, ports=None)` | `None` | Mark an IP as having completed port scanning. Optionally pass the specific `ports: Set[int]` that were tested — these are tracked to avoid re-scanning the same ports in subsequent `PORT_SCAN` stages. |
| `consolidate_devices()` | `int` | Merge devices sharing the same hostname or MAC (useful for IPv6 hosts with multiple addresses). Returns count of removed duplicates. |

---

## ScanPipeline

`lanscape.ScanPipeline`

Sequential executor for an ordered list of stages. Before running each stage, the pipeline checks its `can_execute()` guard. Stages that return a skip reason are marked as skipped and a `ScanWarningInfo(type="stage_skipped")` warning is added to the context.

### Constructor

```python
ScanPipeline(
    stages: List[ScanStageMixin],
    on_stage_change: Callable[[ScanStageMixin], None] | None = None,
    eval_ctx: StageEvalContext | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `stages` | `List[ScanStageMixin]` | *required* | Ordered list of stages to execute |
| `on_stage_change` | `Callable \| None` | `None` | Callback fired when a new stage starts (or is skipped) |
| `eval_ctx` | [`StageEvalContext`](#stageevalcontext) `\| None` | `None` | Pre-built evaluation context. If `None`, built lazily from the subnet at execution time. |

### Methods

| Method | Description |
|--------|-------------|
| `execute(context)` | Run each stage in order, passing the shared context. Skips stages whose `can_execute()` guard returns a reason. |
| `terminate()` | Terminate the current stage and skip remaining stages |
| `append_stages(new_stages)` | Append additional stages to the pipeline. If the pipeline was already terminated, resets the terminated flag so the new stages will execute on the next `execute()` call. |
| `update_stage(index, new_stage)` | Replace a pending (not yet started) stage at the given index with a new stage instance. Raises `ValueError` if the stage is already running or finished. |

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

### Stage Guards

Each built-in discovery stage overrides `can_execute()` to skip itself when the target subnet doesn't match its requirements. The pipeline evaluates these guards automatically — you don't need to filter stages manually.

| Stage | Skips when | Reason |
|-------|-----------|--------|
| `ICMPDiscoveryStage` | IPv6 subnet | ICMP discovery is IPv4-only |
| `ARPDiscoveryStage` | IPv6 subnet, non-local subnet, or ARP unsupported | ARP requires local IPv4 + elevated privileges |
| `PokeARPDiscoveryStage` | IPv6 subnet or non-local subnet | Poke+ARP requires local IPv4 |
| `ICMPARPDiscoveryStage` | IPv6 subnet or non-local subnet | ICMP+ARP requires local IPv4 |
| `IPv6NDPDiscoveryStage` | IPv4 subnet | NDP discovery is IPv6-only |
| `IPv6MDNSDiscoveryStage` | IPv4 subnet | mDNS discovery is IPv6-only |
| `PortScanStage` | *(never skips)* | Runs on any subnet type |

This means you can build a single pipeline with both IPv4 and IPv6 stages — incompatible stages are skipped automatically:

```python
from lanscape import PipelineConfig, StageConfig, StageType, ScanManager

cfg = PipelineConfig(
    subnet="192.168.1.0/24",
    stages=[
        StageConfig(stage_type=StageType.ICMP_ARP_DISCOVERY),
        StageConfig(stage_type=StageType.IPV6_NDP_DISCOVERY),  # auto-skipped for IPv4
        StageConfig(stage_type=StageType.PORT_SCAN),
    ],
)

sm = ScanManager()
scan = sm.new_scan(cfg)
sm.wait_until_complete(scan.uid)

# Check which stages were skipped
for stage in scan.results.get_metadata().stages:
    if stage.skipped:
        print(f"Skipped: {stage.stage_name} — {stage.skip_reason}")
```

---

## Creating Custom Stages

Subclass `ScanStageMixin` to build your own stage. The minimum requirements are:

1. Set `stage_type` and `stage_name` class attributes
2. Implement `execute(context: ScanContext)`
3. Use `self.total`, `self.increment()`, and `self.running` for progress tracking
4. Optionally override `can_execute(eval_ctx)` to add a skip guard

```python
from lanscape import ScanStageMixin, ScanContext, StageType, StageEvalContext
from typing import Optional


class BannerGrabStage(ScanStageMixin):
    """Custom stage: grab banners from open ports on discovered devices."""

    stage_type = StageType.PORT_SCAN  # reuse an existing type, or define your own
    stage_name = "Banner Grab"

    def __init__(self, ports: list[int], timeout: float = 2.0):
        super().__init__()
        self.ports = ports
        self.timeout = timeout

    def can_execute(self, eval_ctx: StageEvalContext) -> Optional[str]:
        # Example: skip banner grabbing on IPv6 subnets
        if eval_ctx.is_ipv6:
            return "Banner grabbing not supported on IPv6"
        return None

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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `stage_name` | `str` | *required* | Human-readable stage name |
| `stage_type` | [`StageType`](../config/enums.md#stagetype) | *required* | Stage type identifier |
| `total` | `int` | `0` | Total work items |
| `completed` | `int` | `0` | Completed work items |
| `finished` | `bool` | `False` | Whether the stage has finished |
| `skipped` | `bool` | `False` | Whether the stage was skipped by a guard |
| `skip_reason` | `str \| None` | `None` | Reason the stage was skipped |
| `runtime` | `float` | `0.0` | Elapsed seconds for this stage |
| `counter_label` | `str` | `"items"` | Label for the progress counter (e.g. `"IPs scanned"`) |
| `auto` | `bool \| None` | `None` | Whether this stage was auto-recommended |
| `reason` | `str \| None` | `None` | Human-readable reason the stage was auto-recommended |

```python
meta = scan.results.get_metadata()
for stage in meta.stages:
    if stage.skipped:
        print(f"{stage.stage_name}: SKIPPED — {stage.skip_reason}")
    else:
        pct = (stage.completed / stage.total * 100) if stage.total else 0
        print(f"{stage.stage_name}: {pct:.0f}% ({'done' if stage.finished else 'running'})")
```

---

## Auto-Stage Recommendation

`lanscape.recommend_stages`

The recommendation engine inspects subnet characteristics and returns an ordered list of suggested stages. The UI uses this to pre-populate the pipeline builder; you can also call it directly.

```python
from lanscape import recommend_stages

recommendations = recommend_stages("192.168.1.0/24")
for rec in recommendations:
    print(f"{rec.stage_type.value} [{rec.preset.value}]: {rec.reason}")
```

### Function signature

```python
recommend_stages(
    subnet: str,
    ip_count: int | None = None,
    is_ipv6: bool | None = None,
    is_local: bool | None = None,
    os_platform: str | None = None,
) -> List[StageRecommendation]
```

All optional parameters are auto-detected from the subnet if not provided. Pass them explicitly to override detection (e.g. for testing).

### StageRecommendation

`lanscape.StageRecommendation`

| Attribute | Type | Description |
|-----------|------|-------------|
| `stage_type` | [`StageType`](../config/enums.md#stagetype) | The recommended stage type |
| `preset` | [`StagePreset`](#stage-presets) | The recommended tuning preset |
| `reason` | `str` | Human-readable explanation |

```python
rec.to_dict()
# {
#   "stage_type": "icmp_arp_discovery",
#   "preset": "accurate",
#   "config": { ... },   # full config dict for the preset
#   "reason": "Small local subnet on Windows — ICMP+ARP is reliable"
# }
```

### Recommendation logic

| Scenario | Recommended stages |
|----------|--------------------|
| IPv6 subnet | `IPV6_NDP_DISCOVERY` + `IPV6_MDNS_DISCOVERY` + `PORT_SCAN` |
| Small local IPv4 (Windows) | `ICMP_ARP_DISCOVERY` (accurate) + `PORT_SCAN` (accurate) |
| Large local IPv4 (Windows) | `POKE_ARP_DISCOVERY` (balanced) + `PORT_SCAN` (balanced) |
| Very large local IPv4 > 25k IPs (Windows) | `POKE_ARP_DISCOVERY` (fast) + `PORT_SCAN` |
| Small/large local IPv4 (Linux/macOS) | `ICMP_ARP_DISCOVERY` + `PORT_SCAN` |
| Non-local IPv4 | `ICMP_DISCOVERY` + `PORT_SCAN` |
| Non-local IPv4 > 25k IPs | *(no recommendation — too large)* |

---

## Stage Presets

`lanscape.StagePreset` · `lanscape.get_stage_presets`

Every stage type ships with three built-in tuning profiles:

| Preset | Description |
|--------|-------------|
| `StagePreset.FAST` | Minimise scan time — reduced timeouts, fewer retries, no hostname retries |
| `StagePreset.BALANCED` | Default Pydantic values — good accuracy/speed trade-off |
| `StagePreset.ACCURATE` | Maximise detection reliability — more retries, longer timeouts, hostname retries |

```python
from lanscape import StagePreset, get_stage_presets, StageConfig, StageType

# Get all preset configs for all stages
presets = get_stage_presets()
# { "icmp_discovery": {"fast": {...}, "balanced": {...}, "accurate": {...}}, ... }

# Use a preset config in a StageConfig
fast_icmp_cfg = presets["icmp_discovery"]["fast"]
stage = StageConfig(
    stage_type=StageType.ICMP_DISCOVERY,
    config=fast_icmp_cfg,
)
```

---

## Stage Time Estimates

`lanscape.estimate_stage_time` · `lanscape.get_all_estimates`

Compute worst-case time estimates for scan stages. Useful for surfacing expected duration to users before a scan starts.

```python
from lanscape import estimate_stage_time, get_all_estimates, StageType

# Single stage estimate (returns seconds per unit of work)
# For discovery stages: seconds per IP
# For PORT_SCAN: seconds per device
secs = estimate_stage_time(
    StageType.ICMP_DISCOVERY,
    config={"ping_config": {"attempts": 2, "timeout": 1.0, "retry_delay": 0.25, "ping_count": 1}},
)
print(f"{secs:.2f}s per IP (worst-case)")

# Multiple stages at once
estimates = get_all_estimates({
    "icmp_discovery": {},   # uses defaults
    "port_scan": {"port_list": "medium"},
})
# { "icmp_discovery": 2.5, "port_scan": 14.8 }
```

### Estimate semantics

| Stage category | Unit | Meaning |
|----------------|------|---------|
| IPv4 discovery (`ICMP_*`, `ARP_*`, `POKE_*`) | per IP | Worst-case seconds to probe one IP (all attempts timed out) |
| IPv6 discovery (`IPV6_NDP_*`, `IPV6_MDNS_*`) | fixed | Fixed overhead for the whole stage |
| `PORT_SCAN` | per device | Worst-case seconds to scan one device (all ports batched by thread count) |

To estimate total scan duration, multiply by subnet size (for discovery) or alive device count (for port scan), then divide by the stage's `t_cnt` thread count.
```
