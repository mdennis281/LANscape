# net_tools

`lanscape.net_tools`

Network utility functions for discovering subnets on your machine, checking ARP support, and hostname resolution.

Internally, `net_tools` is a package split into `device.py` (Device model, hostname resolution) and `subnet_utils.py` (subnet detection, ARP support). All public symbols are re-exported from the package root, so imports remain unchanged.

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
- `127.0.0.0/8` — IPv4 loopback
- `::1/128` — IPv6 loopback
- `fe80::/10` — IPv6 link-local
- `172.27.64.0/20` — WSL default
- `172.17.0.0/16` — Docker default

```python
subnet = net_tools.smart_select_primary_subnet()
# "192.168.1.0/24"
```

---

### `get_all_network_subnets() -> List[dict]`

Get all network subnets on the system, including both IPv4 and IPv6 interfaces. Useful when you want to let the user choose which subnet to scan.

**Returns:** `List[dict]` — each entry has:

| Key | Type | Description |
|-----|------|-------------|
| `"subnet"` | `str` | Subnet in CIDR notation (IPv4 or IPv6) |
| `"address_cnt"` | `int` | Number of scannable hosts in the subnet (capped at 100,000 for large IPv6 subnets) |
| `"interface"` | `str` | Name of the network interface (e.g., `"eth0"`, `"Wi-Fi"`) |

```python
subnets = net_tools.get_all_network_subnets()
# [
#   {"subnet": "192.168.1.0/24", "address_cnt": 254, "interface": "eth0"},
#   {"subnet": "fd00::/64", "address_cnt": 100000, "interface": "eth0"},
#   ...
# ]
```

---

### `get_network_subnet(interface: str | None = None) -> str | None`

Get the subnet for a specific network interface. Returns the first IPv4 or IPv6 subnet found on the interface.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `str \| None` | `None` | Interface name. Defaults to primary interface. |

**Returns:** `str | None` — subnet in CIDR notation (IPv4 or IPv6), or `None` if unavailable.

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

## Subnet Inspection

### `is_ipv6_subnet(subnet: str) -> bool`

Check whether the given subnet string represents an IPv6 network.

```python
net_tools.is_ipv6_subnet("192.168.1.0/24")  # False
net_tools.is_ipv6_subnet("fd00::/64")        # True
```

### `is_local_subnet(subnet: str) -> bool`

Check whether the subnet overlaps with any local network interface on the machine.

```python
net_tools.is_local_subnet("192.168.1.0/24")  # True (if on that LAN)
net_tools.is_local_subnet("10.99.0.0/16")    # False (no local interface)
```

### `matching_interface(subnet: str) -> str | None`

Return the name of the local interface whose network overlaps the given subnet, or `None` if no match.

```python
net_tools.matching_interface("192.168.1.0/24")  # "Wi-Fi"
net_tools.matching_interface("10.99.0.0/16")     # None
```

### `get_os_platform() -> str`

Return the normalised OS platform string: `"windows"`, `"linux"`, or `"darwin"`.

```python
net_tools.get_os_platform()  # "windows"
```

> These functions are the same ones used internally by [`StageEvalContext.build()`](scanner/scan-pipeline.md#stageevalcontext) to populate the evaluation context.

---

## Example: Discover and Scan

```python
from lanscape import ScanManager, ScanConfig, net_tools

# List all subnets on the machine
subnets = net_tools.get_all_network_subnets()
for s in subnets:
    print(f"  {s['subnet']} on {s['interface']}  ({s['address_cnt']} hosts)")

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

---

## Hostname Resolution

During a scan, LANscape resolves hostnames using a multi-strategy approach. This happens automatically — no configuration needed.

| Method | Platform | IPv4 | IPv6 | Description |
|--------|----------|------|------|-------------|
| Reverse DNS | All | ✅ | ✅ | Standard `gethostbyaddr` lookup (PTR records) |
| mDNS PTR query (IPv4) | Linux / macOS | ✅ | — | Multicast DNS query to `224.0.0.251:5353` using `in-addr.arpa` — resolves `.local` hostnames without `avahi-utils` |
| mDNS PTR query (IPv6) | Linux / macOS | — | ✅ | Multicast DNS query to `ff02::fb:5353` using `ip6.arpa` — resolves `.local` hostnames for IPv6 devices |
| NetBIOS NBSTAT | Linux / macOS | ✅ | — | NetBIOS name query on port 137 — IPv4 only, skipped for IPv6 targets |

On **Windows**, the system resolver already chains through NetBIOS, LLMNR, and mDNS, so only reverse DNS is used.

On **Linux and macOS**, if reverse DNS fails, LANscape tries mDNS then NetBIOS as fallbacks. For IPv6 targets, the mDNS query uses `ip6.arpa` PTR records sent via the IPv6 multicast address `ff02::fb`. NetBIOS is skipped since it is an IPv4-only protocol. All fallback methods are implemented in pure Python with no external dependencies.

---

## Cross-Protocol IP Resolution (Alt IPs)

After hostname and MAC resolution, LANscape discovers **alternate IP addresses** for each device. If a device was scanned via IPv4, the resolver looks for its IPv6 addresses, and vice versa. The primary scanned IP and any discovered alt IPs are then classified into `DeviceResult.ipv4_addresses` and `DeviceResult.ipv6_addresses`.

This happens automatically during scanning — no configuration needed.

### Resolution Strategies

| Strategy | Direction | Description |
|----------|-----------|-------------|
| **NDP cache priming** | IPv4 → IPv6 | Pings `ff02::1` (all-nodes multicast) on active interfaces to populate the NDP neighbor table before querying it. Runs once per process. |
| Neighbor-cache correlation | Both | Queries the OS neighbor table (ARP for IPv4, NDP for IPv6) for entries sharing the same MAC |
| EUI-64 link-local derivation | IPv4 → IPv6 | Derives the `fe80::` link-local address from the device's MAC using modified EUI-64 |
| DNS `getaddrinfo` | Both | Queries A or AAAA records for the resolved hostname |

All strategies are best-effort and fail silently. If a network has no IPv6 support, `ipv6_addresses` will only contain the primary IP (when scanning an IPv6 subnet) or be empty.

> **Why NDP priming?** The IPv6 NDP neighbor table is only populated for devices the host has recently communicated with over IPv6. Without priming, most devices discovered via an IPv4 scan would have no IPv6 neighbor entries. The multicast ping triggers NDP responses from all IPv6-capable devices on the link, dramatically increasing coverage.

### Standalone Usage

The resolver can also be used independently:

```python
from lanscape import resolve_alt_ips

# Find IPv6 addresses for a device scanned over IPv4
alt = resolve_alt_ips(
    ip='192.168.1.100',
    macs=['aa:bb:cc:dd:ee:ff'],
    hostname='my-device.local'
)
# ['fe80::a8bb:ccff:fedd:eeff', '2001:db8::100']
```

### Example: Accessing IP Addresses from Scan Results

```python
for device in scan.results.to_results().devices:
    print(f"{device.ip} ({device.hostname})")
    if device.ipv4_addresses:
        print(f"  IPv4: {', '.join(device.ipv4_addresses)}")
    if device.ipv6_addresses:
        print(f"  IPv6: {', '.join(device.ipv6_addresses)}")
```
