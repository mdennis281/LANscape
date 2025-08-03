import asyncio
import logging
import traceback
from .app_scope import ResourceManager

log = logging.getLogger('ServiceScan')
SERVICES = ResourceManager('services').get_jsonc('definitions.jsonc')

# skip printer ports because they cause blank pages to be printed
PRINTER_PORTS = [9100, 631]


def scan_service(ip: str, port: int, timeout=10) -> str:
    """
    Synchronous function that attempts to identify the service running on a given port.
    """

    async def _async_scan_service(ip: str, port: int, timeout) -> str:
        if port in PRINTER_PORTS:
            return "Printer"

        try:
            # Add a timeout to prevent hanging
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=5)

            # Send a probe appropriate for common services
            probe = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(
                ip).encode("utf-8")
            writer.write(probe)
            await writer.drain()

            # Receive the response with a timeout
            response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()

            # Analyze the response to identify the service
            response_str = response.decode("utf-8", errors="ignore")
            for service, hints in SERVICES.items():
                if any(hint.lower() in response_str.lower() for hint in hints):
                    return service
        except asyncio.TimeoutError:
            log.warning(f"Timeout scanning {ip}:{port}")
        except Exception as e:
            log.error(f"Error scanning {ip}:{port}: {str(e)}")
            log.debug(traceback.format_exc())
        return "Unknown"

    # Use asyncio.run to execute the asynchronous logic synchronously
    return asyncio.run(_async_scan_service(ip, port, timeout=timeout))
