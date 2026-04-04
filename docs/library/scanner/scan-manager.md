# ScanManager

`lanscape.ScanManager`

Singleton that manages the lifecycle of all scans. Use it to create new scans, retrieve existing ones, wait for completion, and terminate running scans.

## Import

```python
from lanscape import ScanManager
```

## Usage

```python
sm = ScanManager()

# Create and start a scan (runs in a background thread)
scan = sm.new_scan(config)

# Wait for it to finish
sm.wait_until_complete(scan.uid)

# Retrieve a scan later by ID
scan = sm.get_scan(scan.uid)

# Terminate all running scans
sm.terminate_scans()
```

> **Singleton:** Every call to `ScanManager()` returns the same instance. All scans are tracked in `sm.scans`.

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `scans` | `List[SubnetScanner]` | All scans created during this process lifetime |

## Methods

### `new_scan(config: ScanConfig | PipelineConfig) -> SubnetScanner`

Create and start a new scan in a background thread.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `config` | [`ScanConfig`](../config/scan-config.md) \| [`PipelineConfig`](../config/pipeline-config.md) | Scan configuration — legacy or pipeline format |

**Returns:** [`SubnetScanner`](subnet-scanner.md) — the newly created and running scan instance.

**Behavior:**
- Accepts both `ScanConfig` (auto-converts via `.to_pipeline_config()`) and `PipelineConfig`.
- If the config targets an external subnet with ARP-based scan types, a warning is logged.
- The scan runs in a dedicated `threading.Thread`.
- The scanner is appended to `self.scans` immediately.

---

### `get_scan(scan_id: str) -> SubnetScanner | None`

Retrieve a scan by its UUID.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `str` | The `SubnetScanner.uid` to look up |

**Returns:** The matching `SubnetScanner`, or `None` if not found.

---

### `wait_until_complete(scan_id: str) -> SubnetScanner`

Block until the specified scan finishes.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `str` | The `SubnetScanner.uid` to wait on |

**Returns:** The completed `SubnetScanner` instance.

> Polls `scan.running` every 0.5 seconds.

---

### `terminate_scans() -> None`

Terminate all currently running scans. Calls `scan.terminate()` on each active scan.

## Example: Multiple Sequential Scans

```python
from lanscape import ScanManager, ScanConfig

sm = ScanManager()

subnets = ["192.168.1.0/24", "10.0.0.0/24"]
for subnet in subnets:
    cfg = ScanConfig(subnet=subnet, port_list="small")
    scan = sm.new_scan(cfg)
    sm.wait_until_complete(scan.uid)
    print(scan.results.to_results().model_dump_json(indent=2))

# All scans are still accessible
for scan in sm.scans:
    print(f"{scan.subnet_str}: {scan.results.devices_alive} devices found")
```
