# net_tools

`lanscape.net_tools`

Network utility functions for discovering subnets on your machine and checking ARP support before scanning.

## Import

```python
from lanscape import net_tools
```

---

## Subnet Detection

### `smart_select_primary_subnet(subnets: List[dict] | None = None) -> str`

Intelligently select the primary subnet most likely handling internet traffic. This is the recommended way to determine what to scan.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `subnets` | `List[dict] \| None` | `None` | Pre-fetched subnet list. If `None`, auto-discovers subnets. |

**Returns:** `str` — subnet in CIDR notation (e.g., `"192.168.1.0/24"`), or `""` if none found.

**Selection priority:**
1. Subnet associated with the primary interface (default gateway)
2. Largest non-deprioritized subnet within the maximum IP range
3. Largest deprioritized subnet as fallback
4. First subnet in the list as final fallback

**Deprioritized subnets** (virtual/system networks):
- `127.0.0.0/8` — loopback
- `172.27.64.0/20` — WSL default
- `172.17.0.0/16` — Docker default

```python
subnet = net_tools.smart_select_primary_subnet()
# "192.168.1.0/24"
```

---

### `get_all_network_subnets() -> List[dict]`

Get all network subnets on the system. Useful when you want to let the user choose which subnet to scan.

**Returns:** `List[dict]` — each entry has:

| Key | Type | Description |
|-----|------|-------------|
| `"subnet"` | `str` | Subnet in CIDR notation |
| `"address_cnt"` | `int` | Number of IPs in the subnet |

```python
subnets = net_tools.get_all_network_subnets()
# [{"subnet": "192.168.1.0/24", "address_cnt": 254}, ...]
```

---

### `get_network_subnet(interface: str | None = None) -> str | None`

Get the subnet for a specific network interface.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `str \| None` | `None` | Interface name. Defaults to primary interface. |

**Returns:** `str | None` — subnet in CIDR notation, or `None` if unavailable.

---

## ARP Support

### `is_arp_supported() -> bool`

Check whether active ARP scanning is available on the current system. Useful for deciding which `ScanType` strategies to use.

**Returns:** `bool` — `True` if ARP requests can be sent.

> Requires elevated privileges on most systems. The result is cached after the first call.

```python
from lanscape import ScanConfig, ScanType, net_tools

if net_tools.is_arp_supported():
    lookup = [ScanType.ICMP_THEN_ARP]
else:
    lookup = [ScanType.ICMP]

config = ScanConfig(
    subnet=net_tools.smart_select_primary_subnet(),
    port_list="medium",
    lookup_type=lookup
)
```

---

## Example: Discover and Scan

```python
from lanscape import ScanManager, ScanConfig, net_tools

# List all subnets on the machine
subnets = net_tools.get_all_network_subnets()
for s in subnets:
    print(f"  {s['subnet']}  ({s['address_cnt']} hosts)")

# Auto-pick the best one
primary = net_tools.smart_select_primary_subnet(subnets)
print(f"Scanning: {primary}")

# Run the scan
sm = ScanManager()
scan = sm.new_scan(ScanConfig(subnet=primary, port_list="medium"))
sm.wait_until_complete(scan.uid)

for device in scan.results.to_results().devices:
    print(f"{device.ip} - {device.hostname} - {device.ports}")
```
