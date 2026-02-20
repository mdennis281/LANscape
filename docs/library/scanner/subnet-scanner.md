# SubnetScanner

`lanscape.SubnetScanner`

The scanning engine. Each instance represents a single scan operation targeting a subnet. Created via [`ScanManager.new_scan()`](scan-manager.md), which starts the scan in a background thread.

## Import

```python
from lanscape import SubnetScanner
```

> You typically don't instantiate `SubnetScanner` directly — use `ScanManager.new_scan()` instead.

## Constructor

```python
SubnetScanner(config: ScanConfig)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `config` | [`ScanConfig`](../config/scan-config.md) | Full scan configuration |

Initializes the scanner with:
- Parsed subnet from `config.parse_subnet()`
- Port list from `config.get_ports()`
- A unique scan ID (`uid`)
- A `ScannerResults` instance at `self.results`

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `uid` | `str` | Unique scan identifier (UUID4) |
| `cfg` | `ScanConfig` | The scan configuration |
| `subnet` | `List[IPv4Address]` | Parsed list of IPs to scan |
| `ports` | `List[int]` | Port numbers to test |
| `subnet_str` | `str` | Original subnet string from config |
| `running` | `bool` | Whether the scan is actively executing |
| `results` | [`ScannerResults`](scanner-results.md) | Scan results container |

## Methods

### `start() -> ScannerResults`

Execute the full scan pipeline:

1. **Device discovery** — Tests each IP using the configured `lookup_type` strategies (threaded with automatic retry)
2. **Port scanning** — Tests configured ports on every alive device (if `task_scan_ports` is `True`)
3. **Service detection** — Identifies services on open ports (if `task_scan_port_services` is `True`)

**Returns:** [`ScannerResults`](scanner-results.md) with all discovered devices and metadata.

> Called automatically by `ScanManager.new_scan()` in a background thread.

---

### `terminate() -> bool`

Gracefully terminate a running scan.

**Returns:** `True` if terminated successfully.

**Raises:** `SubnetScanTerminationFailure` if termination takes longer than 10 seconds.

**Behavior:**
- Sets `running = False`
- Moves stage to `terminating`
- Waits up to 10 seconds for active jobs to finish
- Moves stage to `terminated` on success

---

### `calc_percent_complete() -> int`

Calculate an estimated completion percentage (0–100).

**Returns:** `int` — percentage complete. Returns `100` when the scan is no longer running, capped at `99` while still in progress.

Uses a time-based estimation that factors in:
- Average host discovery time per device
- Average port test time per port
- Thread counts and multipliers

---

### `debug_active_scan(sleep_sec: float = 1) -> None`

Interactive console debugger — prints live scan progress to the terminal in a loop while the scan is running. Useful for scripts and development.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sleep_sec` | `float` | `1` | Seconds between refresh cycles |

**Example:**

```python
scan = sm.new_scan(config)
scan.debug_active_scan()  # Blocks until scan completes
```

## Scan Pipeline Detail

```
start()
  ├─ Stage: SCANNING_DEVICES
  │   └─ Threaded pool (t_cnt_isalive workers, with retry)
  │       └─ For each IP:
  │           ├─ Check if device is alive  [ICMP / ARP / Poke]
  │           └─ Get metadata              [hostname, MAC, manufacturer]
  │
  ├─ Stage: TESTING_PORTS  (if task_scan_ports)
  │   └─ Threaded pool (t_cnt_port_scan workers, with retry)
  │       └─ For each alive device:
  │           └─ Threaded pool (t_cnt_port_test workers)
  │               └─ For each port:
  │                   ├─ TCP connect test
  │                   └─ Service identification (if port is open)
  │
  └─ Stage: COMPLETE
```

## Scan Stages

| Stage | Value | Description |
|-------|-------|-------------|
| `INSTANTIATED` | `"instantiated"` | Scanner created, not yet started |
| `SCANNING_DEVICES` | `"scanning devices"` | Device discovery phase |
| `TESTING_PORTS` | `"testing ports"` | Port scanning phase |
| `COMPLETE` | `"complete"` | Scan finished successfully |
| `TERMINATING` | `"terminating"` | Termination requested |
| `TERMINATED` | `"terminated"` | Terminated successfully |
