# ScannerResults

`lanscape.ScannerResults`

Result container attached to every [`SubnetScanner`](subnet-scanner.md). Provides access to discovered devices, scan statistics, and several export methods that produce typed Pydantic models.

## Import

```python
from lanscape import ScannerResults
```

> Accessed via `scanner.results` — you don't instantiate this directly.

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `uid` | `str` | Scan UUID (same as parent scanner) |
| `subnet` | `str` | Target subnet string |
| `port_list` | `str` | Name of the port list used |
| `devices` | `List[Device]` | Internal `Device` objects (alive devices only) |
| `devices_total` | `int` | Total number of IPs in the subnet |
| `devices_scanned` | `int` | Number of IPs that have been checked |
| `devices_alive` | `int` | Number of alive devices (computed: `len(devices)`) |
| `port_list_length` | `int` | Number of ports being tested per device |
| `running` | `bool` | Whether the parent scan is active |
| `stage` | `str` | Current scan stage string |
| `start_time` | `float` | Unix timestamp when the scan started |
| `end_time` | `float \| None` | Unix timestamp when the scan ended |
| `errors` | `List[ScanErrorInfo]` | Scan-level errors (see [`ScanErrorInfo`](../models/overview.md#scanerrorinfo)) |
| `warnings` | `List[ScanWarningInfo]` | Scan-level warnings (see [`ScanWarningInfo`](../models/overview.md#scanwarninginfo)) |

## Methods

### `get_runtime() -> float`

Calculate the scan runtime in seconds.

**Returns:** `float` — seconds elapsed. Uses wall clock time if the scan is still running, or `end_time - start_time` if complete.

---

### `get_metadata() -> ScanMetadata`

Get current scan status and progress as a Pydantic model.

**Returns:** [`ScanMetadata`](../models/overview.md#scanmetadata) — includes scan ID, progress, device counts, timing, errors, and warnings.

---

### `to_results() -> ScanResults`

Export the complete scan results.

**Returns:** [`ScanResults`](../models/overview.md#scanresults) — contains:
- `metadata` — full `ScanMetadata`
- `devices` — list of `DeviceResult` models sorted by IP address (IPv4 first, then IPv6, each group sorted by packed address)
- `config` — the `ScanConfig` serialized as a dict

**Example:**

```python
scan = sm.new_scan(config)
sm.wait_until_complete(scan.uid)

results = scan.results.to_results()
print(results.model_dump_json(indent=2))
```

---

### `to_summary() -> ScanSummary`

Get a lightweight summary of the scan.

**Returns:** [`ScanSummary`](../models/overview.md#scansummary) — contains:
- `metadata` — full `ScanMetadata`
- `ports_found` — sorted list of all unique open ports
- `services_found` — sorted list of all unique service names
- `warnings` — scan-level warnings as `ScanWarningInfo` models

---

### `__str__() -> str`

Pretty-print a table of results using `tabulate`:

```
Scan Results - 192.168.1.0/24 - abc123...
Found/Scanned: 5/254
---------------------------------------------

+---------------+-----------------+-------------------+----------+
| IP            | Host            | MAC               | Ports    |
+===============+=================+===================+==========+
| 192.168.1.1   | router.local    | AA:BB:CC:DD:EE:FF | 80, 443  |
+---------------+-----------------+-------------------+----------+
```

## Example: Accessing Results During a Scan

```python
import time
from lanscape import ScanManager, ScanConfig

sm = ScanManager()
scan = sm.new_scan(ScanConfig(subnet="192.168.1.0/24", port_list="small"))

while scan.running:
    meta = scan.results.get_metadata()
    print(f"Stage: {meta.stage} | Progress: {meta.percent_complete}%")
    print(f"Alive: {meta.devices_alive} / {meta.devices_total}")
    time.sleep(2)

# Final results
summary = scan.results.to_summary()
print(f"Ports found: {summary.ports_found}")
print(f"Services found: {summary.services_found}")
```
