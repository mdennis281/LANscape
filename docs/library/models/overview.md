# Models

Pydantic models used throughout LANscape for structured data exchange. All models support `.model_dump()`, `.model_dump_json()`, and `.model_validate()`.

## Import

```python
from lanscape import (
    DeviceResult, ServiceInfo, ProbeResponseInfo,
    DeviceErrorInfo, ScanErrorInfo, ScanWarningInfo,
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
| `ip` | `str` | *required* | IP address of the device (IPv4 or IPv6) |
| `alive` | `bool \| None` | `None` | Whether the device responded to alive-check |
| `hostname` | `str \| None` | `None` | Resolved hostname (reverse DNS, mDNS, or NetBIOS) |
| `macs` | `List[str]` | `[]` | All discovered MAC addresses (via ARP for IPv4, NDP neighbor cache for IPv6) |
| `manufacturer` | `str \| None` | `None` | MAC vendor/manufacturer name |
| `ipv4_addresses` | `List[str]` | `[]` | All discovered IPv4 addresses for this device (includes the primary IP if it is IPv4, plus any cross-protocol alt IPs) |
| `ipv6_addresses` | `List[str]` | `[]` | All discovered IPv6 addresses for this device (includes the primary IP if it is IPv6, plus any cross-protocol alt IPs) |
| `ports` | `List[int]` | `[]` | Open ports found on the device |
| `stage` | [`DeviceStage`](../config/enums.md#devicestage) | `FOUND` | Current scan stage for this device |
| `ports_scanned` | `int` | `0` | Number of ports that have been tested |
| `services` | `Dict[str, List[int]]` | `{}` | Service name → list of ports mapping (e.g., `{"ssh": [22]}`) |
| `service_info` | `List[ServiceInfo]` | `[]` | Detailed service probe results |
| `errors` | `List[DeviceErrorInfo]` | `[]` | Errors encountered during scanning (port scans, service scans, etc.) |

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

### DeviceErrorInfo

A serializable representation of an error encountered while scanning a specific device. Errors from all scan phases — alive checks, port scans, and service scans — are collected here.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | `str` | *required* | Method or scan phase where the error occurred (e.g., `"scan_service"`, `"_get_hostname"`) |
| `message` | `str` | *required* | Human-readable error message |
| `traceback` | `str \| None` | `None` | Full Python traceback, if available |

Service scan errors (timeouts, connection failures, event-loop errors) are automatically captured and appended to the device's `errors` list. Previously these were silently swallowed — they now surface as `DeviceErrorInfo` entries.

```python
for device in results.devices:
    if device.errors:
        print(f"{device.ip} had {len(device.errors)} error(s):")
        for err in device.errors:
            print(f"  [{err.source}] {err.message}")
```

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
| `ports_scanned` | `int` | `0` | Total port tests completed across all devices |
| `ports_total` | `int` | `0` | Total port tests expected (alive devices × ports) |
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
| `warnings` | `List[ScanWarningInfo]` | `[]` | Scan-level warnings (see [ScanWarningInfo](#scanwarninginfo)) |

---

### ScanErrorInfo

A serializable representation of a scan-level error (as opposed to per-device errors).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `basic` | `str` | *required* | Brief error summary |
| `traceback` | `str \| None` | `None` | Full traceback if available |

---

### ScanWarningInfo

A scan-level warning, typically related to automatic thread-pool tuning. When jobs fail and trigger a multiplier reduction, the warning includes contextual information about the failure — which job failed, the error message, the scan stage, and retry details.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `str` | *required* | Warning type identifier (e.g., `"multiplier_reduced"`) |
| `message` | `str` | *required* | Human-readable warning message |
| `old_multiplier` | `float \| None` | `None` | Previous thread multiplier value |
| `new_multiplier` | `float \| None` | `None` | New thread multiplier value after reduction |
| `decrease_percent` | `float \| None` | `None` | Percent decrease applied |
| `timestamp` | `float \| None` | `None` | Unix timestamp of the warning |
| `failed_job` | `str \| None` | `None` | The job ID (e.g., IP address) that triggered the warning |
| `error_message` | `str \| None` | `None` | The error message from the failed job |
| `stage` | `str \| None` | `None` | The scan stage when the warning occurred (e.g., `"scanning devices"`, `"testing ports"`) |
| `retry_attempt` | `int \| None` | `None` | Which retry attempt failed (1-based) |
| `max_retries` | `int \| None` | `None` | Maximum retries configured for this job type |

The contextual fields (`failed_job`, `error_message`, `stage`, `retry_attempt`, `max_retries`) are populated when a job failure triggers a thread multiplier reduction. They give visibility into *why* the scan is throttling itself.

```python
for warning in results.metadata.warnings:
    print(f"[{warning.type}] {warning.message}")
    if warning.failed_job:
        print(f"  Failed job: {warning.failed_job}")
        print(f"  Error:      {warning.error_message}")
    if warning.stage:
        print(f"  Stage:      {warning.stage}")
    if warning.retry_attempt is not None:
        print(f"  Retry:      {warning.retry_attempt}/{warning.max_retries}")
    if warning.old_multiplier is not None:
        print(f"  Multiplier: {warning.old_multiplier:.2f} -> {warning.new_multiplier:.2f}")
```


