"""Probe execution: TCP connections, TLS detection/escalation, multi-probe dispatch."""

import asyncio
import logging
import ssl
from typing import Optional, Union, List, Tuple

from lanscape.core.scan_config import ServiceScanConfig, ServiceScanStrategy
from lanscape.core.service_scan.models import ProbeResponse, ProbeResult
from lanscape.core.service_scan.resources import (
    SERVICES,
    PROTOCOL_PROBES,
    PORT_SPECIFIC_PROBES,
)
from lanscape.core.service_scan.identification import _identify_service

log = logging.getLogger('ServiceScan')


# Plaintext error messages indicating the server expects HTTPS/TLS.
HTTPS_PLAINTEXT_INDICATORS = [
    "the plain http request was sent to https",
    "this combination of host and port requires tls",
    "you're speaking plain http to an ssl-enabled server",
    "client sent an http request to an https server",
]


async def _try_probe(  # pylint: disable=too-many-locals,too-many-arguments
    ip: str,
    port: int,
    payload: Optional[Union[str, bytes]] = None,
    *,
    timeout: float = 5.0,
    read_len: int = 1024,
    use_ssl: bool = False,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Open a connection, optionally send a payload, and read a single response chunk."""
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
    """Return ``True`` if *data* looks like a TLS record header."""
    if not data or len(data) < 3:
        return False

    valid_content_types = (0x14, 0x15, 0x16, 0x17)
    tls_major_version = 0x03
    valid_minor_versions = (0x01, 0x02, 0x03, 0x04)

    return (data[0] in valid_content_types
            and data[1] == tls_major_version
            and data[2] in valid_minor_versions)


async def _try_ssl_probe(
    ip: str,
    port: int,
    timeout: float = 5.0,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Attempt SSL/TLS connection with an HTTP HEAD probe."""
    return await _try_probe(
        ip, port,
        payload=b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        timeout=timeout,
        use_ssl=True,
    )


async def _handle_tls_escalation(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    ip: str,
    port: int,
    raw_bytes: Optional[bytes],
    decoded_str: Optional[str],
    request: Optional[bytes],
    timeout: float,
) -> Tuple[Optional[str], Optional[bytes], Optional[bytes], bool]:
    """If TLS detected (via bytes, plaintext indicators, or HTTPS redirect), try SSL probe."""
    tls_from_bytes = bool(raw_bytes) and _detect_tls_from_bytes(raw_bytes)

    tls_from_text = False
    https_redirect = False
    if decoded_str and not tls_from_bytes:
        lower = decoded_str.lower()
        tls_from_text = any(ind in lower for ind in HTTPS_PLAINTEXT_INDICATORS)
        if not tls_from_text:
            has_redirect = any(f'{code} ' in lower for code in ['301', '302', '307', '308'])
            has_https_location = 'location: https://' in lower
            https_redirect = has_redirect and has_https_location

    if not tls_from_bytes and not tls_from_text and not https_redirect:
        return (decoded_str, raw_bytes, request, False)

    ssl_raw, ssl_decoded = await _try_ssl_probe(ip, port, timeout)
    ssl_request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    if ssl_decoded and ssl_decoded.strip():
        return (ssl_decoded, ssl_raw, ssl_request, True)

    if tls_from_bytes or tls_from_text:
        return (decoded_str, raw_bytes, request, True)

    return (decoded_str, raw_bytes, request, False)


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
    """Return a list of probe payloads based on the port and strategy."""
    probes = [
        None,
        b"\r\n",
        b"HELP\r\n",
        b"OPTIONS * HTTP/1.0\r\n\r\n",
        b"HEAD / HTTP/1.0\r\n\r\n",
        b"QUIT\r\n",
    ]

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
        for probe in PROTOCOL_PROBES.values():
            if probe is not None and probe not in probes:
                probes.append(probe)
        for _, detail in SERVICES.items():
            if probe := detail.get("probe", ''):
                if probe not in probes:
                    probes.append(probe)
        return probes

    return [None]


async def _multi_probe_generic(  # pylint: disable=too-many-locals,too-many-branches
    ip: str, port: int, cfg: ServiceScanConfig,
) -> ProbeResult:
    """Run probes concurrently and collect responses."""
    aggressive = cfg.lookup_type == ServiceScanStrategy.AGGRESSIVE
    probes = get_port_probes(port, cfg.lookup_type)
    probes_sent = len(probes)
    probes_received = 0
    collected: List[ProbeResponse] = []

    semaphore = asyncio.Semaphore(cfg.max_concurrent_probes)

    async def limited_probe(payload, timeout_val):
        async with semaphore:
            raw_bytes, decoded_str = await _try_probe(
                ip, port, payload, timeout=timeout_val,
            )
            return (payload, raw_bytes, decoded_str)

    tasks = [
        asyncio.create_task(limited_probe(p, cfg.timeout))
        for p in probes
    ]

    found_first = False
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

            escalation = await _handle_tls_escalation(
                ip, port, raw_bytes, decoded_str, payload, cfg.timeout,
            )
            esc_response, esc_bytes, esc_request, esc_tls = escalation

            collected.append(ProbeResponse(
                request=_format_request(esc_request, payload),
                response=esc_response,
                response_bytes=esc_bytes,
                is_tls=esc_tls,
            ))

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
