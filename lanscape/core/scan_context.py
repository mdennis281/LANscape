"""Shared mutable state passed between pipeline stages."""

import logging
import threading
from time import time
from typing import Dict, List, Set

from lanscape.core.net_tools.device import Device
from lanscape.core.models.scan import ScanErrorInfo, ScanWarningInfo

log = logging.getLogger('ScanContext')


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

    def consolidate_devices(self) -> int:
        """Merge devices that belong to the same physical host.

        IPv6 hosts commonly have multiple addresses (SLAAC, privacy
        extensions, temporary).  After discovery and metadata resolution
        each address appears as a separate device.  This method
        consolidates them using two signals:

        1. **Hostname match** — devices sharing the same non-empty
           hostname (case-insensitive) are merged.
        2. **MAC match** — devices sharing any non-empty MAC address
           are merged.

        The first device encountered for a given identity becomes the
        primary; subsequent duplicates have their IPs folded into
        ``primary.merged_ips`` and are removed from the device list.

        Returns the number of devices that were merged away.
        """
        with self._lock:
            # Map each identity key → primary device
            identity_map: Dict[str, Device] = {}
            to_remove: List[Device] = []

            for device in self._devices:
                keys = self._identity_keys(device)
                if not keys:
                    continue

                # Find existing primary for any of this device's keys
                primary: Device | None = None
                for key in keys:
                    if key in identity_map:
                        primary = identity_map[key]
                        break

                if primary is None:
                    # First time seeing this identity — register all keys
                    for key in keys:
                        identity_map[key] = device
                elif primary is not device:
                    # Duplicate — merge into primary
                    primary.merged_ips.append(device.ip)
                    to_remove.append(device)
                    # Also register this device's keys under the primary
                    # so future devices with overlapping keys merge too
                    for key in keys:
                        identity_map[key] = primary
                    log.debug(
                        "Merged %s into %s (keys=%s)",
                        device.ip, primary.ip, keys,
                    )

            for device in to_remove:
                self._devices.remove(device)

            return len(to_remove)

    # Keep backwards-compatible alias
    consolidate_by_hostname = consolidate_devices

    @staticmethod
    def _identity_keys(device: Device) -> List[str]:
        """Return identity keys for a device (hostname and/or MACs)."""
        keys: List[str] = []
        if device.hostname:
            keys.append(f"host:{device.hostname.lower()}")
        for mac in device.macs:
            if mac:
                keys.append(f"mac:{mac.upper()}")
        return keys

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
