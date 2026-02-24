# Models

Pydantic models used throughout LANscape for structured data exchange. All models support `.model_dump()`, `.model_dump_json()`, and `.model_validate()`.

## Import

```python
from lanscape import (
    DeviceResult, ServiceInfo, ProbeResponseInfo,
    ScanMetadata, ScanResults, ScanSummary,
    DeviceStage, ScanStage
)
```

---

## Device Models

### DeviceResult

The primary model for a discovered network device.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip` | `str` | *required* | IP address of the device |
| `alive` | `bool \| None` | `None` | Whether the device responded to alive-check |
| `hostname` | `str \| None` | `None` | Resolved hostname (reverse DNS) |
| `macs` | `List[str]` | `[]` | All discovered MAC addresses |
| `manufacturer` | `str \| None` | `None` | MAC vendor/manufacturer name |
| `ports` | `List[int]` | `[]` | Open ports found on the device |
| `stage` | [`DeviceStage`](../config/enums.md#devicestage) | `FOUND` | Current scan stage for this device |
| `ports_scanned` | `int` | `0` | Number of ports that have been tested |
| `services` | `Dict[str, List[int]]` | `{}` | Service name → list of ports mapping (e.g., `{"ssh": [22]}`) |
| `service_info` | `List[ServiceInfo]` | `[]` | Detailed service probe results |
| `errors` | `List[DeviceErrorInfo]` | `[]` | Errors encountered during scanning |

**Computed field:**

| Field | Type | Description |
|-------|------|-------------|
| `mac_addr` | `str` | Primary MAC address (first in `macs` list, or empty string) |

---

### ServiceInfo

Detailed information about a service discovered on an open port.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | `int` | *required* | Port number |
| `service` | `str` | *required* | Identified service name (e.g., `"SSH"`, `"HTTP"`) |
| `request` | `str \| None` | `None` | The probe/request that elicited a response |
| `response` | `str \| None` | `None` | Raw response from the service |
| `probes_sent` | `int` | `0` | Number of probes sent to this port |
| `probes_received` | `int` | `0` | Number of responses received |
| `is_tls` | `bool` | `False` | Whether TLS/SSL was detected |
| `all_responses` | `List[ProbeResponseInfo]` | `[]` | All probe/response pairs collected during the service scan |

The `all_responses` list contains every individual probe attempt and its result, giving you granular visibility into how a service was identified. The top-level `request` / `response` fields hold the *best match*; `all_responses` holds *everything*.

---

### ProbeResponseInfo

A single probe request/response pair from service detection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `request` | `str \| None` | `None` | Probe payload that was sent |
| `response` | `str \| None` | `None` | Response received from the service |
| `service` | `str` | `"Unknown"` | Service identified for this response |
| `weight` | `int` | `0` | Match confidence weight (higher = more confident) |
| `is_tls` | `bool` | `False` | Whether TLS/SSL was used for this probe |

```python
for device in results.devices:
    for si in device.service_info:
        print(f"Port {si.port}: {si.service}")
        for pr in si.all_responses:
            print(f"  [{pr.weight}] {pr.service} (tls={pr.is_tls})")
            print(f"    Request:  {pr.request}")
            print(f"    Response: {pr.response[:80] if pr.response else 'None'}")
```

---

---

## Scan Models

### ScanMetadata

Scan progress and status metadata — the "header" for a scan.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scan_id` | `str` | *required* | Unique scan identifier (UUID) |
| `subnet` | `str` | *required* | Target subnet being scanned |
| `port_list` | `str` | *required* | Name of port list being used |
| `running` | `bool` | `False` | Whether scan is actively running |
| `stage` | [`ScanStage`](../config/enums.md#scanstage) | `INSTANTIATED` | Current scan lifecycle stage |
| `percent_complete` | `float` | `0.0` | Overall progress (0–100) |
| `devices_total` | `int` | `0` | Total IPs in the target range |
| `devices_scanned` | `int` | `0` | IPs checked so far |
| `devices_alive` | `int` | `0` | Devices found alive |
| `port_list_length` | `int` | `0` | Number of ports being tested per device |
| `start_time` | `float` | `0.0` | Unix timestamp when scan started |
| `end_time` | `float \| None` | `None` | Unix timestamp when scan ended |
| `run_time` | `int` | `0` | Runtime in seconds |
| `errors` | `List[ScanErrorInfo]` | `[]` | Scan-level errors |
| `warnings` | `List[ScanWarningInfo]` | `[]` | Scan-level warnings |

---

### ScanResults

Complete scan results — the full export format.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metadata` | `ScanMetadata` | *required* | Scan status and progress |
| `devices` | `List[DeviceResult]` | `[]` | All discovered devices sorted by IP |
| `config` | `Dict[str, Any] \| None` | `None` | The `ScanConfig` serialized as a dict |

**Example:**

```python
results = scan.results.to_results()
data = results.model_dump_json(indent=2)  # Full JSON export
```

---

### ScanSummary

Lightweight scan summary for progress display.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metadata` | `ScanMetadata` | *required* | Scan status and progress |
| `ports_found` | `List[int]` | `[]` | All unique open ports found across all devices |
| `services_found` | `List[str]` | `[]` | All unique service names identified |
| `warnings` | `List[dict]` | `[]` | Raw warning dicts from the scan |


