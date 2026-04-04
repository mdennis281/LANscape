"""Shared mutable state passed between pipeline stages."""

import threading
from time import time
from typing import Dict, List, Set

from lanscape.core.net_tools.device import Device
from lanscape.core.models.scan import ScanErrorInfo, ScanWarningInfo


class ScanContext:
    """Thread-safe container for data shared across scan stages.

    Each stage can add discovered devices, record errors/warnings, and
    query which devices have not yet been port-scanned (so a repeated
    ``PortScanStage`` only processes newly-found devices).
    """

    def __init__(self, subnet: str) -> None:
        self.subnet: str = subnet
        self.start_time: float = time()

        self._lock = threading.Lock()
        self._devices: List[Device] = []
        self._device_ips: Set[str] = set()
        self._scanned_ports: Dict[str, Set[int]] = {}

        self.errors: List[ScanErrorInfo] = []
        self.warnings: List[ScanWarningInfo] = []

    # ── Device management ───────────────────────────────────────────

    @property
    def devices(self) -> List[Device]:
        """Return a snapshot of discovered devices."""
        with self._lock:
            return list(self._devices)

    def add_device(self, device: Device) -> bool:
        """Add a device if its IP hasn't been seen yet.

        Returns ``True`` if the device was added, ``False`` if duplicate.
        """
        with self._lock:
            if device.ip in self._device_ips:
                return False
            self._device_ips.add(device.ip)
            self._devices.append(device)
            return True

    def get_unscanned_devices(self) -> List[Device]:
        """Return devices that have not had any ports scanned."""
        with self._lock:
            return [d for d in self._devices if d.ip not in self._scanned_ports]

    def get_scanned_ports(self, ip: str) -> Set[int]:
        """Return the set of port numbers already tested for *ip*."""
        with self._lock:
            return set(self._scanned_ports.get(ip, set()))

    def mark_port_scanned(self, ip: str, ports: Set[int] | None = None) -> None:
        """Mark an IP as having completed port scanning.

        If *ports* is provided, the specific port numbers are recorded
        so that future port-scan stages can skip already-tested ports.
        """
        with self._lock:
            existing = self._scanned_ports.get(ip, set())
            if ports is not None:
                existing = existing | ports
            self._scanned_ports[ip] = existing

    @property
    def devices_alive(self) -> int:
        """Return the number of discovered devices."""
        with self._lock:
            return len(self._devices)
