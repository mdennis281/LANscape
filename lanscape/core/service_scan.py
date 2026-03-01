"""Service scanning module for identifying services running on network ports.

Features:
- Multi-probe concurrent scanning
- TLS/SSL detection and secure probing
- Weighted service matching (higher weight = higher priority)
- Binary protocol signature detection

Probe data, binary signatures, and text matchers are loaded from JSONC
resource files under ``lanscape/resources/services/``.
"""

from typing import Optional, Union, List, Tuple, Dict
import asyncio
import logging
import ssl
import traceback

from pydantic import BaseModel, ConfigDict, Field

from lanscape.core.app_scope import ResourceManager
from lanscape.core.scan_config import ServiceScanConfig, ServiceScanStrategy

# asyncio complains more than it needs to
logging.getLogger("asyncio").setLevel(logging.WARNING)

log = logging.getLogger('ServiceScan')

# ── resource manager shared by all loaders ──────────────────────────
_svc_resources = ResourceManager('services')

# Legacy service definitions (hints, ports, probes from definitions.jsonc)
SERVICES = _svc_resources.get_jsonc('definitions.jsonc')

# skip printer ports because they cause blank pages to be printed
PRINTER_PORTS = [9100, 631]


# =============================================================================
# Resource loaders – convert JSONC data into runtime structures
# =============================================================================

class BinarySignature(BaseModel):
    """A binary protocol signature for detecting services by byte patterns."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    pattern: bytes
    weight: int


def _load_binary_signatures() -> List[BinarySignature]:
    """Load binary protocol signatures from ``binary_signatures.jsonc``.

    Each entry has ``name``, ``pattern`` (hex string), and ``weight``.
    Returns a list of :class:`BinarySignature` instances.
    """
    raw = _svc_resources.get_jsonc('binary_signatures.jsonc')
    return [
        BinarySignature(
            name=entry['name'],
            pattern=bytes.fromhex(entry['pattern']),
            weight=entry['weight'],
        )
        for entry in raw
    ]


def _load_protocol_probes() -> Dict[str, Optional[bytes]]:
    """Load protocol-specific probe payloads from ``protocol_probes.jsonc``.

    Values are either:
    - A hex string decoded to bytes.
    - ``null`` (banner-grab only, decoded to ``None``).
    - An object ``{"hex": "<prefix>", "pad_to": <int>}`` for zero-padded
      payloads (e.g. RTMP).
    """
    raw = _svc_resources.get_jsonc('protocol_probes.jsonc')
    probes: Dict[str, Optional[bytes]] = {}
    for name, value in raw.items():
        if value is None:
            probes[name] = None
        elif isinstance(value, dict):
            prefix = bytes.fromhex(value['hex'])
            total = value['pad_to']
            probes[name] = prefix.ljust(total, b'\x00')
        else:
            probes[name] = bytes.fromhex(value)
    return probes


class ServiceMatcher(BaseModel):
    """A pattern matcher for identifying services with weighted priority."""
    name: str
    weight: int
    patterns: List[str] = Field(default_factory=list)
    case_sensitive: bool = False

    def match(self, response: str) -> bool:
        """Check if response matches any pattern."""
        check_response = response if self.case_sensitive else response.lower()
        for pattern in self.patterns:
            check_pattern = pattern if self.case_sensitive else pattern.lower()
            if check_pattern in check_response:
                return True
        return False


def _load_service_matchers() -> List[ServiceMatcher]:
    """Load text-based service matchers from ``service_matchers.jsonc``.

    Each entry is converted into a :class:`ServiceMatcher` instance.
    """
    raw = _svc_resources.get_jsonc('service_matchers.jsonc')
    return [
        ServiceMatcher(
            name=entry['name'],
            weight=entry['weight'],
            patterns=entry.get('patterns', []),
            case_sensitive=entry.get('case_sensitive', False),
        )
        for entry in raw
    ]


def _load_port_specific_probes(
    protocol_probes: Dict[str, Optional[bytes]],
) -> Dict[int, List[Optional[bytes]]]:
    """Load port-to-probe mappings from ``port_probes.jsonc``.

    Keys are port numbers (as strings in JSON), values are lists of
    protocol probe names resolved via *protocol_probes*.
    """
    raw = _svc_resources.get_jsonc('port_probes.jsonc')
    result: Dict[int, List[Optional[bytes]]] = {}
    for port_str, probe_names in raw.items():
        resolved_probes: List[Optional[bytes]] = []
        for name in probe_names:
            probe = protocol_probes.get(name)
            if probe is None and name not in protocol_probes:
                log.warning(
                    "Unknown protocol probe name '%s' referenced for port %s "
                    "in port_probes.jsonc; this entry will be ignored at runtime.",
                    name,
                    port_str,
                )
            resolved_probes.append(probe)
        result[int(port_str)] = resolved_probes
    return result


# ── Load once at import time ────────────────────────────────────────
try:
    BINARY_SIGNATURES: List[BinarySignature] = _load_binary_signatures()
    PROTOCOL_PROBES: Dict[str, Optional[bytes]] = _load_protocol_probes()
    SERVICE_MATCHERS: List[ServiceMatcher] = _load_service_matchers()
    PORT_SPECIFIC_PROBES: Dict[int, List[Optional[bytes]]] = _load_port_specific_probes(
        PROTOCOL_PROBES
    )
except Exception as exc:  # pragma: no cover - defensive import-time guard
    raise RuntimeError(
        "Failed to load service scan resources from 'lanscape/resources/services'. "
        "Ensure all required JSONC files (e.g., 'binary_signatures.jsonc', "
        "'protocol_probes.jsonc', 'service_matchers.jsonc', 'port_probes.jsonc') "
        "are present and valid."
    ) from exc


class ProbeResponse(BaseModel):
    """A single probe's request/response pair."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    request: Optional[str] = None
    response: Optional[str] = None
    response_bytes: Optional[bytes] = None
    is_tls: bool = False
    service: str = 'Unknown'
    weight: int = 0


class ServiceScanResult(BaseModel):
    """Result of a service scan probe."""
    service: str
    response: Optional[str] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False
    all_responses: List['ProbeResponse'] = Field(default_factory=list)
    error: Optional[str] = None


class ProbeResult(BaseModel):
    """Result from multi-probe operation with statistics."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    response: Optional[str] = None
    response_bytes: Optional[bytes] = None
    request: Optional[str] = None
    probes_sent: int = 0
    probes_received: int = 0
    is_tls: bool = False
    all_responses: List[ProbeResponse] = Field(default_factory=list)


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
    """Check for binary protocol signatures. Returns (service_name, weight) or None.
    
    Scans all matching signatures and returns the one with highest weight,
    since signatures can overlap (e.g., RPC and SOCKS5 both use 0x05 0x00).
    """
    if not data:
        return None

    best_name: Optional[str] = None
    best_weight: int = -1

    # Special DNS detection: look for our probe's transaction ID (0xAABB)
    # echoed back with the QR (response) bit set.
    dns_weight = 60
    for offset in range(min(len(data) - 2, 12)):
        if (data[offset] == 0xAA and data[offset + 1] == 0xBB
                and len(data) > offset + 2 and data[offset + 2] & 0x80):
            if dns_weight > best_weight:
                best_name = "DNS"
                best_weight = dns_weight
            break  # DNS transaction ID is definitive

    for sig in BINARY_SIGNATURES:
        if sig.pattern in data:
            if sig.weight > best_weight:
                best_name = sig.name
                best_weight = sig.weight

    if best_name is None:
        return None
    return (best_name, best_weight)


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


# Plaintext error messages that indicate the server expects HTTPS/TLS.
# When detected on a non-TLS response, we attempt an SSL probe.
HTTPS_PLAINTEXT_INDICATORS = [
    "the plain http request was sent to https",
    "this combination of host and port requires tls",
    "you're speaking plain http to an ssl-enabled server",
    "client sent an http request to an https server",
]


async def _handle_tls_escalation(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    ip: str,
    port: int,
    raw_bytes: Optional[bytes],
    decoded_str: Optional[str],
    request: Optional[bytes],
    timeout: float
) -> Tuple[Optional[str], Optional[bytes], Optional[bytes], bool]:
    """If TLS detected (via bytes, plaintext indicators, or HTTPS redirect), try SSL probe."""
    tls_from_bytes = bool(raw_bytes) and _detect_tls_from_bytes(raw_bytes)

    # Check for plaintext indicators of an HTTPS-only port
    tls_from_text = False
    https_redirect = False
    if decoded_str and not tls_from_bytes:
        lower = decoded_str.lower()
        # Explicit error messages telling us "this port is HTTPS"
        tls_from_text = any(ind in lower for ind in HTTPS_PLAINTEXT_INDICATORS)
        # HTTP redirect to HTTPS (e.g. Proxmox 8006, pve-api-daemon)
        if not tls_from_text:
            has_redirect = any(f'{code} ' in lower for code in ['301', '302', '307', '308'])
            has_https_location = 'location: https://' in lower
            https_redirect = has_redirect and has_https_location

    if not tls_from_bytes and not tls_from_text and not https_redirect:
        return (decoded_str, raw_bytes, request, False)

    # TLS detected — try SSL probe for actual service content
    ssl_raw, ssl_decoded = await _try_ssl_probe(ip, port, timeout)
    ssl_request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    if ssl_decoded and ssl_decoded.strip():
        return (ssl_decoded, ssl_raw, ssl_request, True)

    # SSL probe didn't return readable content
    if tls_from_bytes or tls_from_text:
        # Binary TLS or explicit HTTPS error — it IS TLS even without content
        return (decoded_str, raw_bytes, request, True)

    # HTTPS redirect but SSL probe failed — HTTP server with redirect, not HTTPS
    return (decoded_str, raw_bytes, request, False)


async def _multi_probe_generic(  # pylint: disable=too-many-locals,too-many-branches
    ip: str, port: int, cfg: ServiceScanConfig
) -> ProbeResult:
    """
    Run probes in parallel and collect responses.

    In AGGRESSIVE mode every probe runs to completion so the caller can
    pick the highest-weight match.  In LAZY / BASIC mode the first
    meaningful response still short-circuits for speed.

    Returns ProbeResult with the best response plus *all* collected
    probe/response pairs in ``all_responses``.
    """
    aggressive = cfg.lookup_type == ServiceScanStrategy.AGGRESSIVE
    probes = get_port_probes(port, cfg.lookup_type)
    probes_sent = len(probes)
    probes_received = 0
    collected: List[ProbeResponse] = []

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

    # Track whether we already have a usable response (for early-exit modes)
    found_first = False

    # In AGGRESSIVE mode every probe must run to completion, so do NOT
    # impose a global timeout on as_completed — each probe already has
    # its own per-connection timeout via cfg.timeout.  For non-aggressive
    # modes we keep a global cap because we break on the first result and
    # just need a safety net.
    global_timeout: float | None = None if aggressive else cfg.timeout

    try:
        for fut in asyncio.as_completed(tasks, timeout=global_timeout):
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
            if not decoded_str or not decoded_str.strip():
                continue

            # Check for TLS and escalate if needed
            escalation = await _handle_tls_escalation(
                ip, port, raw_bytes, decoded_str, payload, cfg.timeout
            )
            esc_response, esc_bytes, esc_request, esc_tls = escalation

            collected.append(ProbeResponse(
                request=_format_request(esc_request, payload),
                response=esc_response,
                response_bytes=esc_bytes,
                is_tls=esc_tls,
            ))

            # In non-aggressive modes, stop after the first good response
            if not aggressive and not found_first:
                found_first = True
                for t in tasks:
                    if not t.done():
                        t.cancel()
                break
    except asyncio.TimeoutError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # Pick the best response by weight
    best: Optional[ProbeResponse] = None
    for entry in collected:
        svc, weight = _identify_service(
            entry.response or '',
            response_bytes=entry.response_bytes,
            is_tls=entry.is_tls,
        )
        entry.service = svc
        entry.weight = weight
        if best is None or weight > best.weight:
            best = entry

    is_tls = best.is_tls if best else False

    return ProbeResult(
        response=best.response if best else None,
        response_bytes=best.response_bytes if best else None,
        request=best.request if best else None,
        probes_sent=probes_sent,
        probes_received=probes_received,
        is_tls=is_tls,
        all_responses=collected,
    )


def _format_request(
    request: Optional[Union[str, bytes]],
    fallback_payload: Optional[Union[str, bytes]] = None,
) -> Optional[str]:
    """Format a request payload into a display string."""
    value = request if request is not None else fallback_payload
    if value is None:
        return '(banner grab - no request sent)'
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


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


def _strip_redirect_noise(response: str) -> str:
    """Remove ``Location:`` header values before text-based matching.

    Redirect URLs often echo the probe's request path (e.g. ``/wsman``),
    which causes false-positive matches on service keywords like WinRM.
    Stripping Location lines ensures we only match on actual response
    content such as ``Server:``, ``Content-Type:``, and body text.
    """
    if not response:
        return ""
    lines = response.split('\n')
    return '\n'.join(
        line for line in lines
        if not line.strip().lower().startswith('location:')
    )


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

    # Check text-based matchers against redirect-stripped response
    # Redirect Location headers echo probe paths (e.g. /wsman) and
    # cause false-positive keyword matches.
    match_text = _strip_redirect_noise(response)
    for matcher in SERVICE_MATCHERS:
        # HTTPS text matcher should only fire when TLS is confirmed;
        # otherwise body text mentioning "https" (e.g. redirect URLs,
        # error messages) causes false positives.
        if matcher.name == "HTTPS" and not is_tls:
            continue
        if matcher.match(match_text):
            if matcher.weight > best_weight:
                best_service = matcher.name
                best_weight = matcher.weight

    # If no match yet, fall back to legacy SERVICES definitions
    if best_weight == 0 and match_text:
        for service, config in SERVICES.items():
            hints = config.get("hints", [])
            if any(hint.lower() in match_text.lower() for hint in hints):
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
            probe_result = await _multi_probe_generic(ip, port, cfg)

            # Clean up all collected responses for storage
            for entry in probe_result.all_responses:
                if entry.response:
                    entry.response = _clean_response(entry.response)

            if not probe_result.response:
                # Check if we got TLS without readable response
                if probe_result.is_tls:
                    return ServiceScanResult(
                        service="HTTPS", response=None, request=None,
                        probes_sent=probe_result.probes_sent,
                        probes_received=probe_result.probes_received,
                        is_tls=True,
                        all_responses=probe_result.all_responses,
                    )
                return ServiceScanResult(
                    service="Unknown", response=None, request=None,
                    probes_sent=probe_result.probes_sent,
                    probes_received=probe_result.probes_received,
                    all_responses=probe_result.all_responses,
                )

            log.debug(f"Service scan response from {ip}:{port} - {probe_result.response}")

            cleaned_response = _clean_response(probe_result.response)

            # The best service was already identified inside _multi_probe_generic
            # via per-entry _identify_service calls.  Re-derive from the top entry.
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
                is_tls=probe_result.is_tls,
                all_responses=probe_result.all_responses,
            )
        except asyncio.TimeoutError:
            log.warning(f"Timeout scanning {ip}:{port}")
            return ServiceScanResult(
                service="Unknown", response=None, request=None,
                probes_sent=0, probes_received=0,
                error=f"Timeout scanning {ip}:{port}",
            )
        except Exception as e:
            log.error(f"Error scanning {ip}:{port}: {str(e)}")
            log.debug(traceback.format_exc())
            return ServiceScanResult(
                service="Unknown", response=None, request=None,
                probes_sent=0, probes_received=0,
                error=f"Error scanning {ip}:{port}: {str(e)}",
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
            probes_sent=0, probes_received=0,
            error=f"Event loop error scanning {ip}:{port}: {e}",
        )
