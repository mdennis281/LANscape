# PortManager

`lanscape.PortManager`

CRUD manager for port list configurations. Port lists are stored as JSON files on disk, mapping port numbers to service names. The scanner uses these lists to determine which ports to test on each device.

## Import

```python
from lanscape import PortManager
```

## Constructor

```python
pm = PortManager()
```

Creates the port storage directory (`ports/`) if it doesn't exist and initializes an internal `ResourceManager` for file I/O.

## Built-in Port Lists

LANscape ships with several built-in port lists:

| Name | Description |
|------|-------------|
| `small` | ~20 common ports (HTTP, SSH, DNS, etc.) |
| `medium` | ~100 well-known ports |
| `large` | ~1000+ ports for thorough scanning |

## Methods

### `get_port_lists() -> List[str]`

List all available port list names.

**Returns:** `List[str]` — names without the `.json` extension.

```python
pm = PortManager()
print(pm.get_port_lists())
# ['small', 'medium', 'large', 'custom']
```

---

### `get_port_list(port_list: str) -> dict`

Retrieve a port list by name.

| Parameter | Type | Description |
|-----------|------|-------------|
| `port_list` | `str` | Name of the port list |

**Returns:** `dict` — mapping of port number (as string key) to service name.

**Raises:** `ValueError` if the port list does not exist.

```python
ports = pm.get_port_list("small")
# {"22": "SSH", "80": "HTTP", "443": "HTTPS", ...}
```

---

### `create_port_list(port_list: str, data: dict) -> bool`

Create a new port list.

| Parameter | Type | Description |
|-----------|------|-------------|
| `port_list` | `str` | Name for the new port list |
| `data` | `dict` | Mapping of port numbers to service names |

**Returns:** `bool` — `True` if created successfully, `False` if the name already exists or data is invalid.

```python
custom_ports = {
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "9090": "Prometheus"
}
pm.create_port_list("my-custom", custom_ports)
```

---

### `update_port_list(port_list: str, data: dict) -> bool`

Update an existing port list.

| Parameter | Type | Description |
|-----------|------|-------------|
| `port_list` | `str` | Name of the port list to update |
| `data` | `dict` | New mapping of port numbers to service names |

**Returns:** `bool` — `True` if updated, `False` if the list doesn't exist or data is invalid.

---

### `delete_port_list(port_list: str) -> bool`

Delete a port list.

| Parameter | Type | Description |
|-----------|------|-------------|
| `port_list` | `str` | Name of the port list to delete |

**Returns:** `bool` — `True` if deleted, `False` if the list doesn't exist.

---

### `validate_port_data(port_data: dict) -> bool`

Validate port data structure and content.

| Parameter | Type | Description |
|-----------|------|-------------|
| `port_data` | `dict` | Dictionary to validate |

**Returns:** `bool` — `True` if valid.

**Validation rules:**
- Keys must be convertible to `int`
- Values must be `str`
- Port numbers must be in range 0–65535

## Example: Custom Port List with ScanConfig

```python
from lanscape import PortManager, ScanManager, ScanConfig

pm = PortManager()

# Create a focused port list for web servers
web_ports = {
    "80": "HTTP",
    "443": "HTTPS",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "3000": "Dev-Server",
    "5000": "Flask",
    "8000": "Django"
}
pm.create_port_list("web-servers", web_ports)

# Use it in a scan
sm = ScanManager()
config = ScanConfig(subnet="192.168.1.0/24", port_list="web-servers")
scan = sm.new_scan(config)
sm.wait_until_complete(scan.uid)

# Cleanup
pm.delete_port_list("web-servers")
```
