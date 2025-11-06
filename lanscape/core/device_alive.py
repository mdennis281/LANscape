"""
Handles device alive checks using various methods.
"""

import re
import socket
import subprocess
import time
from typing import List
import psutil

from scapy.sendrecv import srp
from scapy.layers.l2 import ARP, Ether
from icmplib import ping
from icmplib.exceptions import SocketPermissionError

from lanscape.core.net_tools import Device, DeviceError
from lanscape.core.scan_config import (
    ScanConfig, ScanType, PingConfig,
    ArpConfig, PokeConfig, ArpCacheConfig
)
from lanscape.core.decorators import timeout_enforcer, job_tracker


def is_device_alive(device: Device, scan_config: ScanConfig) -> bool:
    """
    Check if a device is alive based on the configured scan type.

    Args:
        device (Device): The device to check.
        scan_config (ScanConfig): The configuration for the scan.

    Returns:
        bool: True if the device is alive, False otherwise.
    """
    methods = scan_config.lookup_type

    if ScanType.ICMP in methods:
        IcmpLookup.execute(device, scan_config.ping_config)

    if ScanType.ARP_LOOKUP in methods and not device.alive:
        ArpLookup.execute(device, scan_config.arp_config)

    if ScanType.ICMP_THEN_ARP in methods and not device.alive:
        IcmpLookup.execute(device, scan_config.ping_config)
        ArpCacheLookup.execute(device, scan_config.arp_cache_config)

    if ScanType.POKE_THEN_ARP in methods and not device.alive:
        Poker.execute(device, scan_config.poke_config)
        ArpCacheLookup.execute(device, scan_config.arp_cache_config)

    return device.alive is True


class IcmpLookup():
    """Class to handle ICMP ping lookups for device presence.

    Raises:
        NotImplementedError: If the platform is not supported.

    Returns:
        bool: True if the device is reachable via ICMP, False otherwise.
    """
    @classmethod
    @job_tracker
    def execute(cls, device: Device, cfg: PingConfig) -> bool:
        """Perform an ICMP ping lookup for the specified device.

        Args:
            device (Device): The device to look up.
            cfg (PingConfig): The configuration for the scan.

        Returns:
            bool: True if the device is reachable via ICMP, False otherwise.
        """
        try:
            # Try using icmplib first
            for _ in range(cfg.attempts):
                result = ping(
                    device.ip,
                    count=cfg.ping_count,
                    interval=cfg.retry_delay,
                    timeout=cfg.timeout,
                    privileged=psutil.WINDOWS  # Use privileged mode on Windows
                )
                if result.is_alive:
                    device.alive = True
                    break
            return device.alive is True
        except SocketPermissionError:
            # Fallback to system ping command when raw sockets aren't available
            return cls._ping_fallback(device, cfg)

    @classmethod
    def _ping_fallback(cls, device: Device, cfg: PingConfig) -> bool:
        """Fallback ping using system ping command via subprocess.

        Args:
            device (Device): The device to ping.
            cfg (PingConfig): The ping configuration.

        Returns:
            bool: True if the device responds to ping, False otherwise.
        """
        cmd = []

        if psutil.WINDOWS:
            # -n count, -w timeout in ms
            cmd = ['ping', '-n', str(cfg.ping_count), '-w', str(int(cfg.timeout * 1000)), device.ip]
        else:  # Linux, macOS, and other Unix-like systems
            # -c count, -W timeout in s
            cmd = ['ping', '-c', str(cfg.ping_count), '-W', str(int(cfg.timeout)), device.ip]

        for r in range(cfg.attempts):
            try:
                proc = subprocess.run(
                    cmd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )

                if proc.returncode == 0:
                    output = proc.stdout.lower()

                    # Windows/Linux both include “TTL” on a successful reply
                    if psutil.WINDOWS or psutil.LINUX:
                        if 'ttl' in output:
                            device.alive = True
                            break
                    # some distributions of Linux and macOS
                    if psutil.MACOS or psutil.LINUX:
                        bad = '100.0% packet loss'
                        good = 'ping statistics'
                        # mac doesnt include TTL, so we check good is there, and bad is not
                        if good in output and bad not in output:
                            device.alive = True
                            break
            except subprocess.CalledProcessError as e:
                device.caught_errors.append(DeviceError(e))

            if r < cfg.attempts - 1:
                time.sleep(cfg.retry_delay)

        return device.alive is True


class ArpCacheLookup():
    """
    Class to handle ARP cache lookups for device presence.
    """

    @classmethod
    @job_tracker
    def execute(cls, device: Device, cfg: ArpCacheConfig) -> bool:
        """
        Perform an ARP cache lookup for the specified device.

        Args:
            device (Device): The device to look up.

        Returns:
            bool: True if the device is found in the ARP cache, False otherwise.
        """

        command = cls._get_platform_arp_command() + [device.ip]

        for _ in range(cfg.attempts):
            time.sleep(cfg.wait_before)
            output = subprocess.check_output(command).decode()
            macs = cls._extract_mac_address(output)
            if macs:
                device.macs = macs
                device.alive = True
                break

        return device.alive is True

    @classmethod
    def _get_platform_arp_command(cls) -> List[str]:
        """
        Get the ARP command to execute based on the platform.

        Returns:
            list[str]: The ARP command to execute.
        """
        if psutil.WINDOWS:
            return ['arp', '-a']
        if psutil.LINUX:
            return ['arp', '-n']
        if psutil.MACOS:
            return ['arp', '-n']

        raise NotImplementedError("Unsupported platform")

    @classmethod
    def _extract_mac_address(cls, arp_resp: str) -> List[str]:
        """
        Extract MAC addresses from ARP output.

        Args:
            arp_resp (str): The ARP command output.

        Returns:
            List[str]: A list of extracted MAC addresses (may be empty).
        """
        arp_resp = arp_resp.replace('-', ':')
        return re.findall(r'..:..:..:..:..:..', arp_resp)


class ArpLookup():
    """
    Class to handle ARP lookups for device presence.
    NOTE: This lookup method requires elevated privileges to access the ARP cache.


    [Arp Lookup Requirements](/docs/arp-issues.md)
    """

    @classmethod
    @job_tracker
    def execute(cls, device: Device, cfg: ArpConfig) -> bool:
        """
        Perform an ARP lookup for the specified device.

        Args:
            device (Device): The device to look up.

        Returns:
            bool: True if the device is found via ARP, False otherwise.
        """
        enforcer_timeout = cfg.timeout * 2

        @timeout_enforcer(enforcer_timeout, raise_on_timeout=True)
        def do_arp_lookup():
            arp_request = ARP(pdst=device.ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=cfg.timeout, verbose=False)
            alive = any(resp.psrc == device.ip for _, resp in answered)
            macs = []
            if alive:
                macs = [resp.hwsrc for _, resp in answered if resp.psrc == device.ip]
            return alive, macs

        alive, macs = do_arp_lookup()
        if alive:
            device.alive = True
            device.macs = macs

        return device.alive is True


class Poker():
    """
    Class to handle Poking the device to populate the ARP cache.
    """

    @classmethod
    @job_tracker
    def execute(cls, device: Device, cfg: PokeConfig):
        """
        Perform a Poke for the specified device.
        Note: the purpose of this is to simply populate the arp cache.

        Args:
            device (Device): The device to look up.
            cfg (PokeConfig): The configuration for the Poke lookup.

        Returns:
            None: used to populate the arp cache
        """
        enforcer_timeout = cfg.timeout * cfg.attempts * 2

        @timeout_enforcer(enforcer_timeout, raise_on_timeout=True)
        def do_poke():
            # Use a small set of common ports likely to be filtered but still trigger ARP
            common_ports = [80, 443, 22]
            for i in range(cfg.attempts):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(cfg.timeout)
                port = common_ports[i % len(common_ports)]
                sock.connect_ex((device.ip, port))
                sock.close()

        do_poke()
