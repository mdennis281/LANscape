"""Top-level ``scan_service`` entry point."""

import asyncio
import logging
import traceback

from lanscape.core.scan_config import ServiceScanConfig
from lanscape.core.service_scan.models import ServiceScanResult
from lanscape.core.service_scan.resources import PRINTER_PORTS
from lanscape.core.service_scan.identification import _identify_service, _clean_response
from lanscape.core.service_scan.probes import _multi_probe_generic

log = logging.getLogger('ServiceScan')


def scan_service(ip: str, port: int, cfg: ServiceScanConfig) -> ServiceScanResult:
    """Synchronous wrapper that identifies the service running on *ip*:*port*."""

    async def _async_scan_service(
        ip: str, port: int, cfg: ServiceScanConfig,
    ) -> ServiceScanResult:
        if port in PRINTER_PORTS:
            return ServiceScanResult(
                service="Printer", response=None, request=None,
                probes_sent=0, probes_received=0,
            )

        try:
            probe_result = await _multi_probe_generic(ip, port, cfg)

            for entry in probe_result.all_responses:
                if entry.response:
                    entry.response = _clean_response(entry.response)

            if not probe_result.response:
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

            service_name, weight = _identify_service(
                probe_result.response,
                response_bytes=probe_result.response_bytes,
                is_tls=probe_result.is_tls,
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

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_async_scan_service(ip, port, cfg=cfg))
    except Exception as e:
        log.error(f"Event loop error scanning {ip}:{port}: {e}")
        return ServiceScanResult(
            service="Unknown", response=None, request=None,
            probes_sent=0, probes_received=0,
            error=f"Event loop error scanning {ip}:{port}: {e}",
        )
    finally:
        asyncio.set_event_loop(None)
        loop.close()
