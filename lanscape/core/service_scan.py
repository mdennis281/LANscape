"""Service scanning module for identifying services running on network ports.

Features:
- Multi-probe concurrent scanning
- TLS/SSL detection and secure probing
- Weighted service matching (higher weight = higher priority)
- Binary protocol signature detection
"""

from dataclasses import dataclass, field
from typing import Optional, Union, List, Tuple
import asyncio
import logging
import ssl
import traceback

from lanscape.core.app_scope import ResourceManager
from lanscape.core.scan_config import ServiceScanConfig, ServiceScanStrategy

# asyncio complains more than it needs to
logging.getLogger("asyncio").setLevel(logging.WARNING)

log = logging.getLogger('ServiceScan')
SERVICES = ResourceManager('services').get_jsonc('definitions.jsonc')

# skip printer ports because they cause blank pages to be printed
PRINTER_PORTS = [9100, 631]


# =============================================================================
# Binary Protocol Signatures - detect protocols by byte patterns
# =============================================================================
BINARY_SIGNATURES = [
    # (name, pattern_bytes, weight)
    # TLS/SSL Alert or Handshake
    ("TLS", b"\x15\x03", 50),  # TLS Alert
    ("TLS", b"\x16\x03", 50),  # TLS Handshake

    # SMB/NetBIOS - Windows file sharing
    ("SMB", b"\xffSMB", 60),  # SMB1 response
    ("SMB", b"\xfeSMB", 60),  # SMB2/3 response
    ("NetBIOS", b"\x83\x00\x00\x01", 55),  # NetBIOS negative session response
    ("NetBIOS", b"\x82\x00\x00\x00", 55),  # NetBIOS positive session response

    # RDP (Remote Desktop) - X.224 connection confirm
    ("RDP", b"\x03\x00\x00", 55),  # TPKT header
    ("RDP", b"\x03\x00", 50),  # Short TPKT

    # RPC/DCE
    ("RPC", b"\x05\x00", 45),  # DCE/RPC version 5

    # MySQL greeting
    ("MySQL", b"\x00\x00\x00\x0a", 40),  # MySQL protocol v10

    # PostgreSQL
    ("PostgreSQL", b"SFATAL", 40),
    ("PostgreSQL", b"SERROR", 40),
    ("PostgreSQL", b"E", 35),  # PostgreSQL error response single byte

    # Redis
    ("Redis", b"+PONG", 40),
    ("Redis", b"-ERR", 30),
    ("Redis", b"-NOAUTH", 45),  # Redis auth required

    # MongoDB
    ("MongoDB", b"ismaster", 40),

    # SSH (already text but good to have)
    ("SSH", b"SSH-", 50),

    # VNC
    ("VNC", b"RFB ", 55),  # RFB protocol version

    # DNS responses (binary)
    ("DNS", b"\x00\x00\x81\x80", 40),  # Standard query response
    ("DNS", b"\x00\x00\x81\x83", 40),  # Name error response

    # SOCKS5 proxy
    ("SOCKS5", b"\x05\x00", 55),  # SOCKS5 no auth required
    ("SOCKS5", b"\x05\xff", 55),  # SOCKS5 no acceptable methods
    ("SOCKS5", b"\x05\x02", 55),  # SOCKS5 auth methods

    # RTMP (Flash Media Server)
    ("RTMP", b"\x03\x00\x00\x00", 50),  # RTMP handshake S0

    # Sun RPC / Portmapper
    ("SunRPC", b"\x00\x00\x00\x1c", 45),  # RPC reply header
    ("SunRPC", b"\x80\x00", 40),  # RPC fragment header

    # MQTT
    ("MQTT", b"\x20\x02", 55),  # CONNACK
    ("MQTT", b"\x10", 35),  # CONNECT packet type

    # Printer protocols
    ("LPD", b"\x00", 25),  # LPD ACK
    ("IPP", b"\x01\x01", 40),  # IPP version 1.1
]

# =============================================================================
# Protocol-specific probes for better service detection
# =============================================================================
PROTOCOL_PROBES = {
    # SMB negotiate - minimal SMB1 negotiate request
    "SMB": b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x00"
           b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           b"\x00\x0c\x00\x02NT LM 0.12\x00",

    # RDP X.224 connection request
    "RDP": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",

    # NetBIOS session request
    "NetBIOS": b"\x81\x00\x00D *SMBSERVER\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 WORKSTATION\x00\x00\x00\x00"
               b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    # Redis PING
    "Redis": b"*1\r\n$4\r\nPING\r\n",

    # MySQL initial handshake (just wait for banner)
    "MySQL": None,  # MySQL sends banner automatically

    # VNC version request (just connect and wait)
    "VNC": None,

    # PostgreSQL SSL request
    "PostgreSQL": b"\x00\x00\x00\x08\x04\xd2\x16/",

    # SOCKS5 version identification/method selection
    "SOCKS5": b"\x05\x01\x00",  # SOCKS5, 1 method, no auth

    # RTMP handshake C0+C1
    "RTMP": b"\x03" + (b"\x00" * 1536),  # C0 version + C1 zeros (simplified)

    # Sun RPC portmapper getport (NFS)
    "SunRPC": b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02"
              b"\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              b"\x00\x00\x00\x00",

    # MQTT CONNECT packet (minimal)
    "MQTT": b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x01x",
}


# =============================================================================
# Weighted Service Matchers - text patterns with priority weights
# =============================================================================
@dataclass
class ServiceMatcher:
    """A pattern matcher for identifying services with weighted priority."""
    name: str
    weight: int
    patterns: List[str] = field(default_factory=list)
    case_sensitive: bool = False

    def match(self, response: str) -> bool:
        """Check if response matches any pattern."""
        check_response = response if self.case_sensitive else response.lower()
        for pattern in self.patterns:
            check_pattern = pattern if self.case_sensitive else pattern.lower()
            if check_pattern in check_response:
                return True
        return False


# Service matchers ordered by specificity (more specific = higher weight)
SERVICE_MATCHERS = [
    # WebSocket gets high priority (often contains HTTP headers too)
    ServiceMatcher("WebSocket", weight=100, patterns=[
        "websocket", "upgrade: websocket", "sec-websocket", "ws://"
    ]),

    # gRPC / HTTP/2
    ServiceMatcher("gRPC", weight=90, patterns=[
        "grpc", "application/grpc", "PRI * HTTP/2"
    ]),

    # TLS/HTTPS (high priority, detected by binary or text)
    ServiceMatcher("HTTPS", weight=80, patterns=[
        "https", "ssl", "tls", "certificate"
    ]),

    # API-specific (higher than generic HTTP)
    ServiceMatcher("REST API", weight=70, patterns=[
        "application/json", '"api"', '"version"', '"status"'
    ]),

    # Common web servers
    ServiceMatcher("HTTP", weight=50, patterns=[
        "http/1.", "http/2", "apache", "nginx", "iis", "lighttpd",
        "gunicorn", "caddy", "cloudflare", "server:", "content-type:"
    ]),

    # Databases
    ServiceMatcher("Redis", weight=60, patterns=["+pong", "redis"]),
    ServiceMatcher("MongoDB", weight=60, patterns=["mongodb", "ismaster"]),
    ServiceMatcher("MySQL", weight=60, patterns=["mysql", "mariadb"]),
    ServiceMatcher("PostgreSQL", weight=55, patterns=["postgresql", "postgres", "fatal:", "psql"]),

    # Remote access
    ServiceMatcher("SSH", weight=70, patterns=["ssh-", "openssh", "dropbear"]),
    ServiceMatcher("Telnet", weight=40, patterns=["telnet", "login:"]),

    # Mail
    ServiceMatcher("SMTP", weight=60, patterns=["smtp", "220 ", "postfix", "exim"]),
    ServiceMatcher("IMAP", weight=60, patterns=["imap", "* ok"]),
    ServiceMatcher("POP3", weight=60, patterns=["+ok", "pop3"]),

    # File transfer
    ServiceMatcher("FTP", weight=60, patterns=["ftp", "220-", "vsftpd", "filezilla"]),

    # Messaging
    ServiceMatcher("MQTT", weight=60, patterns=["mqtt"]),
    ServiceMatcher("AMQP", weight=60, patterns=["amqp", "rabbitmq"]),

    # Minecraft (specific)
    ServiceMatcher("Minecraft", weight=70, patterns=["minecraft"]),

    # DNS (rare to get text response but possible)
    ServiceMatcher("DNS", weight=40, patterns=["dns", "bind", "named"]),

    # Windows Services - important for enterprise networks
    ServiceMatcher("SMB", weight=65, patterns=["smb", "samba", "netbios", "cifs"]),
    ServiceMatcher("RDP", weight=65, patterns=[
        "rdp", "remote desktop", "terminal service", "ms-wbt-server"
    ]),
    ServiceMatcher("RPC", weight=55, patterns=["rpc", "dcerpc", "endpoint mapper"]),
    ServiceMatcher("WinRM", weight=60, patterns=["wsman", "winrm", "windows remote"]),
    ServiceMatcher("WSDAPI", weight=55, patterns=[
        "wsdapi", "microsoft-httpapi", "web services"
    ]),
    ServiceMatcher("LDAP", weight=60, patterns=["ldap", "active directory"]),

    # Apple/AirPlay
    ServiceMatcher("AirTunes", weight=65, patterns=["airtunes", "airplay"]),
    ServiceMatcher("mDNS", weight=50, patterns=["mdns", "bonjour", "_tcp.local"]),

    # IoT & Home Automation
    ServiceMatcher("UPnP", weight=50, patterns=["upnp", "ssdp", "igd:"]),
    ServiceMatcher("Plex", weight=65, patterns=["plex", "x-plex"]),
    ServiceMatcher("HomeAssistant", weight=65, patterns=["home assistant", "hass"]),

    # VNC
    ServiceMatcher("VNC", weight=60, patterns=["rfb ", "vnc", "tightvnc", "realvnc"]),

    # Streaming
    ServiceMatcher("RTSP", weight=55, patterns=["rtsp/", "real time streaming"]),
    ServiceMatcher("RTMP", weight=55, patterns=["rtmp", "flash media", "fms/"]),

    # Databases (additional)
    ServiceMatcher("Elasticsearch", weight=60, patterns=["elasticsearch", "lucene"]),
    ServiceMatcher("Memcached", weight=55, patterns=["memcached", "stat "]),

    # Proxy protocols
    ServiceMatcher("SOCKS5", weight=60, patterns=["socks", "socks5"]),
    ServiceMatcher("Squid", weight=55, patterns=["squid", "proxy"]),

    # RPC/Portmapper
    ServiceMatcher("SunRPC", weight=50, patterns=["portmapper", "rpcbind", "nfs"]),
    ServiceMatcher("NFS", weight=55, patterns=["nfs", "mount"]),

    # Printers
    ServiceMatcher("Printer", weight=55, patterns=["printer", "jetdirect", "cups", "lpd"]),
    ServiceMatcher("IPP", weight=55, patterns=["ipp", "internet printing"]),

    # Google Cast / Chromecast
    ServiceMatcher("GoogleCast", weight=60, patterns=["chromecast", "google cast", "eureka"]),

    # Spotify Connect
    ServiceMatcher("SpotifyConnect", weight=60, patterns=["spotify", "spotifyconnect"]),

    # Common IoT
    ServiceMatcher("Roku", weight=60, patterns=["roku"]),
    ServiceMatcher("Sonos", weight=60, patterns=["sonos"]),
]


@dataclass
class ServiceScanResult:
    """Result of a service scan probe."""
    service: str
    response: Optional[str] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False


@dataclass
class ProbeResult:
    """Result from multi-probe operation with statistics."""
    response: Optional[str] = None
    response_bytes: Optional[bytes] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False


async def _try_probe(  # pylint: disable=too-many-locals,too-many-arguments
    ip: str,
    port: int,
    payload: Optional[Union[str, bytes]] = None,
    *,
    timeout: float = 5.0,
    read_len: int = 1024,
    use_ssl: bool = False,
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Open a connection, optionally send a payload, and read a single response chunk.
    Returns tuple of (raw_bytes, decoded_string) or (None, None).
    """
    try:
        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=timeout
        )
        try:
            if payload is not None:
                data = payload if isinstance(
                    payload, (bytes, bytearray)) else str(payload).encode(
                    "utf-8", errors="ignore")
                writer.write(data)
                await writer.drain()
            try:
                response = await asyncio.wait_for(reader.read(read_len), timeout=timeout / 2)
            except asyncio.TimeoutError:
                response = b""
            resp_str = response.decode("utf-8", errors="replace") if response else ""
            return (response if response else None, resp_str if resp_str else None)
        finally:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass
    except Exception as e:
        expected_types = (ConnectionResetError, ConnectionRefusedError, TimeoutError, OSError)
        expected_errnos = {10054, 10061, 10060}
        eno = getattr(e, 'errno', None)
        if isinstance(e, expected_types) and (eno in expected_errnos or eno is None):
            return (None, None)
        log.debug(f"Probe error on {ip}:{port} - {repr(e)}")
        return (None, None)


def _detect_tls_from_bytes(data: bytes) -> bool:
    """
    Check if response bytes indicate TLS/SSL.

    Detects TLS by checking for valid TLS record layer header format:
    - Byte 0: Content type (0x14-0x17)
    - Byte 1: Major version (0x03 for all TLS versions)
    - Byte 2: Minor version (0x01-0x04 for TLS 1.0-1.3)

    Supported versions:
    - TLS 1.0 (0x0301)
    - TLS 1.1 (0x0302)
    - TLS 1.2 (0x0303)
    - TLS 1.3 (0x0304) - Note: TLS 1.3 often uses 0x0303 in record layer for compatibility

    Args:
        data: Raw bytes from server response

    Returns:
        True if data appears to be a TLS record, False otherwise
    """
    if not data or len(data) < 3:
        return False

    # TLS record types:
    # 0x14 = ChangeCipherSpec
    # 0x15 = Alert
    # 0x16 = Handshake
    # 0x17 = ApplicationData
    valid_content_types = (0x14, 0x15, 0x16, 0x17)

    # All TLS versions use 0x03 as major version byte
    # Minor version: 0x01=TLS1.0, 0x02=TLS1.1, 0x03=TLS1.2, 0x04=TLS1.3
    # Note: TLS 1.3 may advertise 0x0303 in record layer for middlebox compatibility
    tls_major_version = 0x03
    valid_minor_versions = (0x01, 0x02, 0x03, 0x04)

    if (data[0] in valid_content_types and
            data[1] == tls_major_version and
            data[2] in valid_minor_versions):
        return True
    return False


def _match_binary_signature(data: bytes) -> Optional[Tuple[str, int]]:
    """Check for binary protocol signatures. Returns (service_name, weight) or None."""
    if not data:
        return None
    for name, pattern, weight in BINARY_SIGNATURES:
        if pattern in data:
            return (name, weight)
    return None


async def _try_ssl_probe(
    ip: str,
    port: int,
    timeout: float = 5.0,
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Attempt SSL/TLS connection and get server info.
    Returns tuple of (raw_bytes, decoded_string).
    """
    # Try with HTTP probe over SSL
    return await _try_probe(
        ip, port,
        payload=b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        timeout=timeout,
        use_ssl=True
    )


async def _handle_tls_escalation(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    ip: str,
    port: int,
    raw_bytes: bytes,
    decoded_str: str,
    request: Optional[bytes],
    timeout: float
) -> Tuple[str, Optional[bytes], Optional[bytes], bool]:
    """If TLS detected, try SSL probe and return updated values."""
    if not raw_bytes or not _detect_tls_from_bytes(raw_bytes):
        return (decoded_str, raw_bytes, request, False)
    # TLS detected - try SSL probe for actual service
    ssl_raw, ssl_decoded = await _try_ssl_probe(ip, port, timeout)
    if ssl_decoded and ssl_decoded.strip():
        return (
            ssl_decoded, ssl_raw,
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            True
        )
    return (decoded_str, raw_bytes, request, True)


async def _multi_probe_generic(  # pylint: disable=too-many-locals,too-many-branches
    ip: str, port: int, cfg: ServiceScanConfig
) -> ProbeResult:
    """
    Run a small set of generic probes in parallel and return the first non-empty response.
    If TLS is detected, will retry with SSL wrapper.
    Returns ProbeResult with response and probe statistics.
    """
    probes = get_port_probes(port, cfg.lookup_type)
    probes_sent = len(probes)
    probes_received = 0
    response_found = None
    response_bytes_found = None
    request_used = None
    is_tls = False

    semaphore = asyncio.Semaphore(cfg.max_concurrent_probes)

    async def limited_probe(payload, timeout_val):
        async with semaphore:
            raw_bytes, decoded_str = await _try_probe(
                ip, port, payload,
                timeout=timeout_val
            )
            return (payload, raw_bytes, decoded_str)

    tasks = [
        asyncio.create_task(limited_probe(p, cfg.timeout))
        for p in probes
    ]

    try:
        for fut in asyncio.as_completed(tasks, timeout=cfg.timeout):
            try:
                result = await fut
            except Exception:
                result = None
            if result is None:
                continue

            payload, raw_bytes, decoded_str = result
            if raw_bytes is None and decoded_str is None:
                continue

            probes_received += 1
            if not decoded_str or not decoded_str.strip() or response_found is not None:
                continue

            # Found a meaningful response - check for TLS and escalate if needed
            escalation = await _handle_tls_escalation(
                ip, port, raw_bytes, decoded_str, payload, cfg.timeout
            )
            response_found, response_bytes_found, request_used, is_tls = escalation

            # Cancel remaining tasks since we found a good response
            for t in tasks:
                if not t.done():
                    t.cancel()
            break
    except asyncio.TimeoutError:
        pass
    finally:
        # Ensure remaining tasks are cancelled and awaited to suppress warnings
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # Format the request for display
    request_display = None
    if request_used is not None:
        if isinstance(request_used, bytes):
            request_display = request_used.decode('utf-8', errors='replace')
        else:
            request_display = str(request_used)
    elif response_found is not None:
        # Response came from banner grab (None payload)
        request_display = "(banner grab - no request sent)"

    return ProbeResult(
        response=response_found,
        response_bytes=response_bytes_found,
        request=request_display,
        probes_sent=probes_sent,
        probes_received=probes_received,
        is_tls=is_tls
    )


# Port-specific binary probes for protocols that need special handling
PORT_SPECIFIC_PROBES = {
    # SMB/NetBIOS - ports 139, 445
    139: [PROTOCOL_PROBES.get("NetBIOS")],
    445: [PROTOCOL_PROBES.get("SMB")],
    # RDP - port 3389
    3389: [PROTOCOL_PROBES.get("RDP")],
    # Redis - port 6379
    6379: [PROTOCOL_PROBES.get("Redis")],
    # PostgreSQL - port 5432
    5432: [PROTOCOL_PROBES.get("PostgreSQL")],
    # SOCKS5 - port 1080
    1080: [PROTOCOL_PROBES.get("SOCKS5")],
    # RTMP - port 1935
    1935: [PROTOCOL_PROBES.get("RTMP")],
    # Sun RPC/Portmapper - port 111
    111: [PROTOCOL_PROBES.get("SunRPC")],
    # MQTT - ports 1883, 8883
    1883: [PROTOCOL_PROBES.get("MQTT")],
    8883: [PROTOCOL_PROBES.get("MQTT")],
    # NFS - port 2049
    2049: [PROTOCOL_PROBES.get("SunRPC")],
}


def get_port_probes(port: int, strategy: ServiceScanStrategy):
    """
    Return a list of probe payloads based on the port and strategy.

    Includes generic probes plus port-specific probes for better detection.
    """
    probes = [
        None,  # banner-first protocols (SSH/FTP/SMTP/etc.)
        b"\r\n",  # nudge for many line-oriented services
        b"HELP\r\n",  # sometimes yields usage/help (SMTP/POP/IMAP-ish)
        b"OPTIONS * HTTP/1.0\r\n\r\n",  # elicit Server header without path
        b"HEAD / HTTP/1.0\r\n\r\n",  # basic HTTP
        b"QUIT\r\n",  # graceful close if understood
    ]

    # Add port-specific probes for any strategy
    if port in PORT_SPECIFIC_PROBES:
        port_probes = [p for p in PORT_SPECIFIC_PROBES[port] if p is not None]
        probes.extend(port_probes)

    if strategy == ServiceScanStrategy.LAZY:
        return probes

    if strategy == ServiceScanStrategy.BASIC:
        for _, detail in SERVICES.items():
            if port in detail.get("ports", []):
                if probe := detail.get("probe", ''):
                    probes.append(probe)
        return probes

    if strategy == ServiceScanStrategy.AGGRESSIVE:
        # Add all protocol probes
        for probe in PROTOCOL_PROBES.values():
            if probe is not None and probe not in probes:
                probes.append(probe)
        # Add service-specific probes from definitions
        for _, detail in SERVICES.items():
            if probe := detail.get("probe", ''):
                if probe not in probes:
                    probes.append(probe)
        return probes

    return [None]  # Default to banner grab only


# Maximum length for stored responses to avoid bloating results
MAX_RESPONSE_LENGTH = 512


def _clean_response(response: str) -> str:
    """
    Clean up a response string for storage.

    - Strips leading/trailing whitespace
    - Replaces control characters with readable representations
    - Truncates to MAX_RESPONSE_LENGTH
    """
    if not response:
        return ""

    # Strip whitespace
    cleaned = response.strip()

    # Replace null bytes and other problematic control chars
    # Keep newlines, tabs, and carriage returns as they're meaningful
    cleaned = ''.join(
        char if char.isprintable() or char in '\n\r\t' else f'\\x{ord(char):02x}'
        for char in cleaned
    )

    # Truncate if too long
    if len(cleaned) > MAX_RESPONSE_LENGTH:
        cleaned = cleaned[:MAX_RESPONSE_LENGTH] + '...'

    return cleaned


def _identify_service(
    response: str,
    response_bytes: Optional[bytes] = None,
    is_tls: bool = False
) -> Tuple[str, int]:
    """
    Identify service using weighted matching.

    Checks both binary signatures and text patterns, returns the highest-weight match.
    Falls back to legacy SERVICES config if no matcher found.

    Args:
        response: Decoded response string
        response_bytes: Raw response bytes (for binary signature matching)
        is_tls: Whether TLS was detected on the connection

    Returns:
        Tuple of (service_name, weight). Weight 0 means unknown.
    """
    best_service = "Unknown"
    best_weight = 0

    # If TLS was detected, start with HTTPS as baseline
    if is_tls:
        best_service = "HTTPS"
        best_weight = 80

    # Check binary signatures first (more reliable)
    if response_bytes:
        match = _match_binary_signature(response_bytes)
        if match:
            sig_name, sig_weight = match
            if sig_weight > best_weight:
                best_service = sig_name
                best_weight = sig_weight

    # Check text-based matchers
    for matcher in SERVICE_MATCHERS:
        if matcher.match(response):
            if matcher.weight > best_weight:
                best_service = matcher.name
                best_weight = matcher.weight

    # If no match yet, fall back to legacy SERVICES definitions
    if best_weight == 0 and response:
        for service, config in SERVICES.items():
            hints = config.get("hints", [])
            if any(hint.lower() in response.lower() for hint in hints):
                best_service = service
                best_weight = 30  # Legacy matches get low weight
                break

    return (best_service, best_weight)


def scan_service(ip: str, port: int, cfg: ServiceScanConfig) -> ServiceScanResult:
    """
    Synchronous function that attempts to identify the service
    running on a given port.

    Returns:
        ServiceScanResult with service name, raw response, and probe statistics
    """

    async def _async_scan_service(
        ip: str, port: int,
        cfg: ServiceScanConfig
    ) -> ServiceScanResult:
        if port in PRINTER_PORTS:
            return ServiceScanResult(
                service="Printer", response=None, request=None,
                probes_sent=0, probes_received=0
            )

        try:
            # Run multiple generic probes concurrently and take first useful response
            probe_result = await _multi_probe_generic(ip, port, cfg)

            if not probe_result.response:
                # Check if we got TLS without readable response
                if probe_result.is_tls:
                    return ServiceScanResult(
                        service="HTTPS", response=None, request=None,
                        probes_sent=probe_result.probes_sent,
                        probes_received=probe_result.probes_received,
                        is_tls=True
                    )
                return ServiceScanResult(
                    service="Unknown", response=None, request=None,
                    probes_sent=probe_result.probes_sent,
                    probes_received=probe_result.probes_received
                )

            log.debug(f"Service scan response from {ip}:{port} - {probe_result.response}")

            # Clean up response for storage (limit length, strip control chars)
            cleaned_response = _clean_response(probe_result.response)

            # Use weighted matching to identify the service
            service_name, weight = _identify_service(
                probe_result.response,
                response_bytes=probe_result.response_bytes,
                is_tls=probe_result.is_tls
            )

            log.debug(f"Service identified: {service_name} (weight={weight})")

            return ServiceScanResult(
                service=service_name,
                response=cleaned_response,
                request=probe_result.request,
                probes_sent=probe_result.probes_sent,
                probes_received=probe_result.probes_received,
                is_tls=probe_result.is_tls
            )
        except asyncio.TimeoutError:
            log.warning(f"Timeout scanning {ip}:{port}")
        except Exception as e:
            log.error(f"Error scanning {ip}:{port}: {str(e)}")
            log.debug(traceback.format_exc())
        return ServiceScanResult(
            service="Unknown", response=None, request=None,
            probes_sent=0, probes_received=0
        )

    # Create and properly manage event loop to avoid file descriptor leaks
    # Using new_event_loop + explicit close is safer in threaded environments
    # than asyncio.run() which can leave resources open under heavy load
    loop = None
    try:
        try:
            # Try to get existing loop first (if running in async context)
            loop = asyncio.get_running_loop()
            # If we're already in an async context, just await directly
            return asyncio.run_coroutine_threadsafe(
                _async_scan_service(ip, port, cfg=cfg), loop
            ).result(timeout=cfg.timeout + 5)
        except RuntimeError:
            # No running loop, create a new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_async_scan_service(ip, port, cfg=cfg))
            finally:
                # Clean up the loop properly
                try:
                    # Cancel all remaining tasks
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    # Run loop once more to process cancellations
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                finally:
                    loop.close()
    except Exception as e:
        log.error(f"Event loop error scanning {ip}:{port}: {e}")
        return ServiceScanResult(
            service="Unknown", response=None, request=None,
            probes_sent=0, probes_received=0
        )
