"""Device model and related helpers (hostname resolution, MAC selection)."""

import logging
import socket
import struct
from time import sleep
from typing import List, Dict, Optional

from pydantic import BaseModel, PrivateAttr, ConfigDict, computed_field, model_serializer

from lanscape.core.service_scan import scan_service, ServiceScanResult
from lanscape.core.mac_lookup import MacLookup, get_macs
from lanscape.core.errors import DeviceError
from lanscape.core.decorators import job_tracker, timeout_enforcer
from lanscape.core.scan_config import ServiceScanConfig, PortScanConfig
from lanscape.core.models import (
    DeviceResult, DeviceErrorInfo, DeviceStage, ServiceInfo, ProbeResponseInfo
)
from lanscape.core.system_compat import (
    os_handles_hostname_resolution,
    get_socket_family,
    is_ipv6,
    resolve_hostname_avahi,
    resolve_hostname_dnssd,
    resolve_hostname_llmnr,
)
from lanscape.core.alt_ip_resolver import resolve_alt_ips

log = logging.getLogger('NetTools')
mac_lookup = MacLookup()


# ---------------------------------------------------------------------------
# Pure-Python hostname resolution helpers
# ---------------------------------------------------------------------------

def _dns_name_decode(data: bytes, offset: int) -> tuple:
    """Decode a DNS-encoded name from *data* starting at *offset*.

    Handles label-compression pointers (RFC 1035 §4.1.4).
    Returns ``(name_str, next_offset)``.
    """
    labels: list = []
    max_offset = offset
    jumped = False
    seen: set = set()

    while offset < len(data):
        if offset in seen:
            break
        seen.add(offset)

        length = data[offset]
        if length == 0:
            if not jumped:
                max_offset = offset + 1
            break

        if (length & 0xC0) == 0xC0:
            if not jumped:
                max_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length

    return '.'.join(labels), max_offset


def _parse_mdns_ptr_response(data: bytes) -> Optional[str]:
    """Extract the hostname from an mDNS PTR response packet."""
    if len(data) < 12:
        return None

    flags = struct.unpack('>H', data[2:4])[0]
    if not flags & 0x8000:
        return None

    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    if ancount == 0:
        return None

    offset = 12
    for _ in range(qdcount):
        _, offset = _dns_name_decode(data, offset)
        offset += 4

    for _ in range(ancount):
        _, offset = _dns_name_decode(data, offset)
        if offset + 10 > len(data):
            return None
        rtype = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 8
        rdlength = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2

        if rtype == 12:
            hostname, _ = _dns_name_decode(data, offset)
            return hostname.rstrip('.') if hostname else None
        offset += rdlength

    return None


def _parse_nbstat_response(data: bytes) -> Optional[str]:
    """Extract the machine name from a NetBIOS NBSTAT response."""
    if len(data) < 43:
        return None

    offset = 12
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            offset += 2
            break
        offset += 1 + length

    if offset + 10 > len(data):
        return None
    offset += 10

    if offset >= len(data):
        return None
    num_names = data[offset]
    offset += 1

    for _ in range(num_names):
        if offset + 18 > len(data):
            break
        name_bytes = data[offset:offset + 15]
        suffix = data[offset + 15]
        flags = struct.unpack('>H', data[offset + 16:offset + 18])[0]
        offset += 18

        if suffix == 0x00 and not flags & 0x8000:
            name = name_bytes.decode('ascii', errors='ignore').strip()
            if name and name != '*':
                return name

    return None


# ---------------------------------------------------------------------------
# Device model
# ---------------------------------------------------------------------------

class Device(BaseModel):
    """Represents a network device with metadata and scanning capabilities."""

    ip: str
    alive: Optional[bool] = None
    hostname: Optional[str] = None
    macs: List[str] = []
    manufacturer: Optional[str] = None
    ports: List[int] = []
    stage: str = 'found'
    ports_scanned: int = 0
    services: Dict[str, List[int]] = {}
    service_info: List[ServiceInfo] = []
    caught_errors: List[DeviceError] = []
    job_stats: Optional[Dict] = None
    alt_ips: List[str] = []
    ipv4_addresses: List[str] = []
    ipv6_addresses: List[str] = []

    _log: logging.Logger = PrivateAttr(default_factory=lambda: logging.getLogger('Device'))
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def log(self) -> logging.Logger:
        """Get the logger instance for this device."""
        return self._log

    @computed_field(return_type=str)
    @property
    def mac_addr(self) -> str:
        """Get the primary MAC address for this device."""
        return self.get_mac() or ""

    @model_serializer(mode='wrap')
    def _serialize(self, serializer):
        """Serialize device data for output."""
        data = serializer(self)
        data.pop('job_stats', None)
        data['mac_addr'] = data.get('mac_addr') or (self.get_mac() or '')
        manuf = data.get('manufacturer')
        if not manuf:
            data['manufacturer'] = self._get_manufacturer(
                data['mac_addr']) if data['mac_addr'] else None
        return data

    def get_metadata(self):
        """Retrieve metadata such as hostname, MAC addresses, and alternate IPs."""
        if self.alive:
            self.hostname = self._get_hostname()
            self._get_mac_addresses()
            if not self.manufacturer:
                self.manufacturer = self._get_manufacturer(
                    self.get_mac()
                )
            self._resolve_alt_ips()

    def test_port(self, port: int, port_config: Optional[PortScanConfig] = None) -> bool:
        """Test if a specific port is open on the device."""
        if port_config is None:
            port_config = PortScanConfig()

        enforcer_timeout = port_config.timeout * (port_config.retries + 1) * 1.5
        family = get_socket_family(self.ip)

        @timeout_enforcer(enforcer_timeout, False)
        def do_test():
            for attempt in range(port_config.retries + 1):
                sock = None
                try:
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(port_config.timeout)
                    result = sock.connect_ex((self.ip, port))
                    if result == 0:
                        if port not in self.ports:
                            self.ports.append(port)
                        return True
                except OSError as e:
                    log_port = logging.getLogger('Device.test_port')
                    log_port.debug(f"OSError on {self.ip}:{port} attempt {attempt + 1}: {e}")
                except Exception:
                    pass
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass

                if attempt < port_config.retries:
                    sleep(port_config.retry_delay)

            return False

        ans = do_test() or False
        self.ports_scanned += 1
        return ans

    @job_tracker
    def scan_service(self, port: int, cfg: ServiceScanConfig):
        """Scan a specific port for services."""
        try:
            result: ServiceScanResult = scan_service(self.ip, port, cfg)
        except Exception as e:
            self.caught_errors.append(DeviceError(e))
            return

        if result.error:
            try:
                raise RuntimeError(result.error)
            except RuntimeError as err:
                self.caught_errors.append(DeviceError(err))

        service_ports = self.services.get(result.service, [])
        service_ports.append(port)
        self.services[result.service] = service_ports

        self.service_info.append(ServiceInfo(
            port=port,
            service=result.service,
            request=result.request,
            response=result.response,
            probes_sent=result.probes_sent,
            probes_received=result.probes_received,
            is_tls=result.is_tls,
            all_responses=[
                ProbeResponseInfo(
                    request=pr.request,
                    response=pr.response,
                    service=pr.service,
                    weight=pr.weight,
                    is_tls=pr.is_tls,
                ) for pr in result.all_responses
            ],
        ))

    def get_mac(self):
        """Get the primary MAC address of the device."""
        if not self.macs:
            return ''
        return mac_selector.choose_mac(self.macs)

    @job_tracker
    def _get_mac_addresses(self):
        """Get the possible MAC addresses of a network device given its IP address."""
        if not self.macs:
            self.macs = get_macs(self.ip)
        mac_selector.import_macs(self.macs)
        return self.macs

    @job_tracker
    def _get_hostname(self) -> Optional[str]:
        """Get the hostname via reverse DNS, with mDNS/NetBIOS/LLMNR fallbacks.

        Resolution order:
        1. socket.gethostbyaddr() - standard reverse DNS
        2. avahi-resolve (Linux) or dns-sd (macOS) - system mDNS daemons
        3. Raw mDNS PTR query - pure Python multicast
        4. LLMNR query - for Windows devices on the network
        5. NetBIOS NBSTAT - IPv4 only, for older Windows devices
        """
        # 1. Standard reverse DNS
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            if hostname:
                return hostname
        except socket.herror:
            pass

        if os_handles_hostname_resolution():
            return None

        # 2. System mDNS daemon (avahi on Linux, dns-sd on macOS)
        hostname = resolve_hostname_avahi(self.ip)
        if hostname:
            return hostname

        hostname = resolve_hostname_dnssd(self.ip)
        if hostname:
            return hostname

        # 3. Raw mDNS PTR query
        hostname = self._resolve_mdns()
        if hostname:
            return hostname

        # 4. LLMNR (useful for Windows devices)
        hostname = resolve_hostname_llmnr(self.ip)
        if hostname:
            return hostname

        # 5. NetBIOS (IPv4 only)
        hostname = self._resolve_netbios()
        if hostname:
            return hostname

        return None

    def _resolve_mdns(self) -> Optional[str]:
        """Resolve hostname via mDNS multicast PTR query (pure Python, IPv4 & IPv6)."""
        if is_ipv6(self.ip):
            return self._resolve_mdns_v6()
        return self._resolve_mdns_v4()

    def _resolve_mdns_v4(self) -> Optional[str]:
        """Resolve hostname via IPv4 mDNS PTR query."""
        reversed_ip = '.'.join(reversed(self.ip.split('.')))
        qname = f"{reversed_ip}.in-addr.arpa"

        name_bytes = b''
        for label in qname.split('.'):
            name_bytes += bytes([len(label)]) + label.encode('ascii')
        name_bytes += b'\x00'

        request = (
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x01'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
        ) + name_bytes + (
            b'\x00\x0c'
            b'\x80\x01'
        )

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.sendto(request, ('224.0.0.251', 5353))
            data, _ = sock.recvfrom(1500)
            return _parse_mdns_ptr_response(data)
        except (socket.timeout, OSError):
            return None
        finally:
            if sock:
                sock.close()

    def _resolve_mdns_v6(self) -> Optional[str]:
        """Resolve hostname via IPv6 mDNS PTR query."""
        import ipaddress as _ipaddress  # pylint: disable=import-outside-toplevel
        addr = _ipaddress.IPv6Address(self.ip)
        nibbles = addr.exploded.replace(':', '')
        reversed_nibbles = '.'.join(reversed(nibbles))
        qname = f"{reversed_nibbles}.ip6.arpa"

        name_bytes = b''
        for label in qname.split('.'):
            name_bytes += bytes([len(label)]) + label.encode('ascii')
        name_bytes += b'\x00'

        request = (
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x01'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
        ) + name_bytes + (
            b'\x00\x0c'   # PTR record
            b'\x80\x01'   # QU flag + IN class
        )

        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)

            # Determine scope_id for link-local multicast (ff02::fb) based on
            # the interface used to reach the target IPv6 address.
            scope_id = 0
            try:
                info = socket.getaddrinfo(
                    str(addr), 0, socket.AF_INET6, socket.SOCK_DGRAM
                )
                if info and len(info[0]) >= 5 and len(info[0][4]) >= 4:
                    scope_id = info[0][4][3]
            except OSError:
                scope_id = 0

            if scope_id:
                sock.sendto(request, ('ff02::fb', 5353, 0, scope_id))
            else:
                sock.sendto(request, ('ff02::fb', 5353))

            data, _ = sock.recvfrom(1500)
            return _parse_mdns_ptr_response(data)
        except (socket.timeout, OSError):
            return None
        finally:
            if sock:
                sock.close()

    def _resolve_netbios(self) -> Optional[str]:
        """Resolve hostname via NetBIOS NBSTAT query (pure Python, IPv4 only)."""
        if is_ipv6(self.ip):
            return None
        request = (
            b'\xa5\x6c'
            b'\x00\x00'
            b'\x00\x01'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x20'
            b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            b'\x00'
            b'\x00\x21'
            b'\x00\x01'
        )

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(request, (self.ip, 137))
            data, _ = sock.recvfrom(1500)
            return _parse_nbstat_response(data)
        except (socket.timeout, OSError):
            return None
        finally:
            if sock:
                sock.close()

    @job_tracker
    def _get_manufacturer(self, mac_addr=None):
        """Get the manufacturer of a network device given its MAC address."""
        return mac_lookup.lookup_vendor(mac_addr) if mac_addr else None

    @job_tracker
    def _resolve_alt_ips(self):
        """Discover cross-protocol IP addresses (IPv4<->IPv6) for this device."""
        try:
            self.alt_ips = resolve_alt_ips(self.ip, self.macs, self.hostname)
        except Exception as exc:  # pylint: disable=broad-except
            self._log.debug("Alt-IP resolution failed for %s: %s", self.ip, exc)
            self.alt_ips = []

        # Classify primary IP + alt IPs into protocol buckets
        all_ips = [self.ip] + self.alt_ips
        self.ipv4_addresses = [ip for ip in all_ips if not is_ipv6(ip)]
        self.ipv6_addresses = [ip for ip in all_ips if is_ipv6(ip)]

    def to_result(self) -> DeviceResult:
        """Convert this Device to a DeviceResult for API/WebSocket responses."""
        error_infos = []
        for err in self.caught_errors:
            error_infos.append(DeviceErrorInfo(
                source=err.method if hasattr(err, 'method') else 'unknown',
                message=str(err.base) if hasattr(err, 'base') else str(err),
                traceback=None
            ))

        stage_map = {
            'found': DeviceStage.FOUND,
            'scanning': DeviceStage.SCANNING,
            'complete': DeviceStage.COMPLETE
        }
        device_stage = stage_map.get(self.stage, DeviceStage.FOUND)

        return DeviceResult(
            ip=self.ip,
            alive=self.alive,
            hostname=self.hostname,
            macs=self.macs,
            manufacturer=self.manufacturer or self._get_manufacturer(self.get_mac()),
            ports=self.ports,
            ports_scanned=self.ports_scanned,
            stage=device_stage,
            services=self.services,
            service_info=self.service_info,
            errors=error_infos,
            ipv4_addresses=self.ipv4_addresses,
            ipv6_addresses=self.ipv6_addresses,
        )


# ---------------------------------------------------------------------------
# MAC selector
# ---------------------------------------------------------------------------

class MacSelector:
    """Filters out duplicate/spurious MACs by choosing the least-seen address."""

    def __init__(self):
        self.macs = {}

    def choose_mac(self, macs: List[str]) -> str:
        """Return the MAC address seen the fewest times."""
        if len(macs) == 1:
            return macs[0]
        lowest = 9999
        lowest_i = -1
        for mac in macs:
            count = self.macs.get(mac, 0)
            if count < lowest:
                lowest = count
                lowest_i = macs.index(mac)
        return macs[lowest_i] if lowest_i != -1 else None

    def import_macs(self, macs: List[str]):
        """Record a batch of MAC addresses seen for a device."""
        for mac in macs:
            self.macs[mac] = self.macs.get(mac, 0) + 1

    def clear(self):
        """Clear the stored MAC addresses."""
        self.macs = {}


mac_selector = MacSelector()
