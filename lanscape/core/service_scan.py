"""Service scanning module for identifying services running on network ports.
"""

from typing import Optional, Union
import sys
import asyncio
import logging
import traceback

from lanscape.core.app_scope import ResourceManager
from lanscape.core.scan_config import ServiceScanConfig, ServiceScanStrategy

log = logging.getLogger('ServiceScan')
SERVICES = ResourceManager('services').get_jsonc('definitions.jsonc')

# skip printer ports because they cause blank pages to be printed
PRINTER_PORTS = [9100, 631]


async def _try_probe(
    ip: str,
    port: int,
    payload: Optional[Union[str, bytes]] = None,
    *,
    timeout: float = 5.0,
    read_len: int = 1024,
) -> Optional[str]:
    """
    Open a connection, optionally send a payload, and read a single response chunk.
    Returns the decoded response string or None.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
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
            resp_str = response.decode("utf-8", errors="ignore") if response else ""
            return resp_str if resp_str else None
        finally:
            # Guarded close to avoid surfacing connection-lost noise
            try:
                writer.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception:
                pass
    except Exception as e:
        # Suppress common/expected network errors that simply indicate no useful banner
        expected_types = (ConnectionResetError, ConnectionRefusedError, TimeoutError, OSError)
        expected_errnos = {10054, 10061, 10060}  # reset, refused, timeout (Win specific)
        eno = getattr(e, 'errno', None)
        if isinstance(e, expected_types) and (eno in expected_errnos or eno is None):
            return None
        log.debug(f"Probe error on {ip}:{port} - {repr(e)}")
        return None


async def _multi_probe_generic(
    ip: str, port: int, cfg: ServiceScanConfig
) -> Optional[str]:
    """
    Run a small set of generic probes in parallel and return the first non-empty response.
    """
    probes = get_port_probes(port, cfg.lookup_type)

    semaphore = asyncio.Semaphore(cfg.max_concurrent_probes)

    async def limited_probe(ip, port, payload, timeout_val):
        async with semaphore:
            return await _try_probe(
                ip, port, payload,
                timeout=timeout_val
            )

    tasks = [
        asyncio.create_task(
            limited_probe(ip, port, p, cfg.timeout)
        )
        for p in probes
    ]

    try:
        for fut in asyncio.as_completed(tasks, timeout=cfg.timeout):
            try:
                resp = await fut
            except Exception:
                resp = None
            if resp and resp.strip():
                # Cancel remaining tasks
                for t in tasks:
                    if not t.done():
                        t.cancel()
                return resp
    except asyncio.TimeoutError:
        pass
    finally:
        # Ensure remaining tasks are cancelled and awaited to suppress warnings
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    return None


def get_port_probes(port: int, strategy: ServiceScanStrategy):
    """
    Return a list of probe payloads based on the port and strategy.
    """
    # For now, we use generic probes for all ports.
    # This can be extended to use specific probes per port/service.

    probes = [
        None,  # banner-first protocols (SSH/FTP/SMTP/etc.)
        b"\r\n",  # nudge for many line-oriented services
        b"HELP\r\n",  # sometimes yields usage/help (SMTP/POP/IMAP-ish)
        b"OPTIONS * HTTP/1.0\r\n\r\n",  # elicit Server header without path
        b"HEAD / HTTP/1.0\r\n\r\n",  # basic HTTP
        b"QUIT\r\n",  # graceful close if understood
    ]

    if strategy == ServiceScanStrategy.LAZY:
        return probes

    if strategy == ServiceScanStrategy.BASIC:
        for _, detail in SERVICES.items():
            if port in detail.get("ports", []):
                if probe := detail.get("probe", ''):
                    probes.append(probe)
        return probes

    if strategy == ServiceScanStrategy.AGGRESSIVE:
        for _, detail in SERVICES.items():
            if probe := detail.get("probe", ''):
                probes.append(probe)
        return probes

    return [None]  # Default to banner grab only


def scan_service(ip: str, port: int, cfg: ServiceScanConfig) -> str:
    """
    Synchronous function that attempts to identify the service running on a given port.
    """

    async def _async_scan_service(
        ip: str, port: int,
        cfg: ServiceScanConfig
    ) -> str:
        if port in PRINTER_PORTS:
            return "Printer"

        try:
            # Run multiple generic probes concurrently and take first useful response
            response_str = await _multi_probe_generic(ip, port, cfg)
            if not response_str:
                return "Unknown"

            log.debug(f"Service scan response from {ip}:{port} - {response_str}")

            # Analyze the response to identify the service
            for service, config in SERVICES.items():
                if any(hint.lower() in response_str.lower() for hint in config.get("hints", [])):
                    return service
        except asyncio.TimeoutError:
            log.warning(f"Timeout scanning {ip}:{port}")
        except Exception as e:
            log.error(f"Error scanning {ip}:{port}: {str(e)}")
            log.debug(traceback.format_exc())
        return "Unknown"

    # Use asyncio.run to execute the asynchronous logic synchronously
    return asyncio.run(_async_scan_service(ip, port, cfg=cfg))


def asyncio_logger_suppression():
    """Suppress the noisy asyncio transport errors since they are expected in service scanning."""

    # Reduce noisy asyncio transport errors on Windows by switching to Selector policy
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    # Also tone down asyncio logger noise from transport callbacks
    try:
        logging.getLogger("asyncio").setLevel(logging.WARNING)
    except Exception:
        pass


asyncio_logger_suppression()

