"""Handles device alive checks using various methods."""

import socket
import subprocess
import time
from typing import List

from icmplib import ping
from icmplib.exceptions import SocketPermissionError

from lanscape.core.net_tools import Device, DeviceError
from lanscape.core.scan_config import (
    ScanConfig, ScanType, PingConfig,
    ArpConfig, PokeConfig, ArpCacheConfig
)
from lanscape.core.decorators import timeout_enforcer, job_tracker
from lanscape.core.system_compat import (
    get_arp_cache_command,
    get_arp_lookup_command,
    icmp_requires_privileged,
    get_ping_command,
    parse_ping_success,
    extract_mac_from_output,
    send_arp_request,
    is_ipv6,
    get_socket_family,
)


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
    """ICMP ping-based device reachability check."""
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
            for _ in range(cfg.attempts):
                result = ping(
                    device.ip,
                    count=cfg.ping_count,
                    interval=cfg.retry_delay,
                    timeout=cfg.timeout,
                    privileged=icmp_requires_privileged()
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
        """Fallback ping using system ping command via subprocess."""
        cmd = get_ping_command(cfg.ping_count, int(cfg.timeout * 1000), device.ip)

        for r in range(cfg.attempts):
            try:
                timeout_val = cfg.timeout * cfg.ping_count + 5
                proc = subprocess.run(
                    cmd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_val,
                    check=False
                )

                if proc.returncode == 0 and parse_ping_success(proc.stdout):
                    device.alive = True
                    return True

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    FileNotFoundError) as e:
                device.caught_errors.append(DeviceError(e))

            if r < cfg.attempts - 1:
                time.sleep(cfg.retry_delay)

        return device.alive is True


class ArpCacheLookup():
    """
    Class to handle ARP/NDP cache lookups for device presence.
    Uses ARP cache for IPv4 and NDP neighbor cache for IPv6.
    """

    @classmethod
    @job_tracker
    def execute(cls, device: Device, cfg: ArpCacheConfig) -> bool:
        """
        Perform an ARP/NDP cache lookup for the specified device.

        Args:
            device (Device): The device to look up.

        Returns:
            bool: True if the device is found in the cache, False otherwise.
        """
        ipv6 = is_ipv6(device.ip)

        try:
            if ipv6:
                # IPv6: use shell-based NDP neighbor command
                command = get_arp_lookup_command(device.ip)
                use_shell = True
            else:
                # IPv4: use list-based ARP command
                command = cls._get_platform_arp_command() + [device.ip]
                use_shell = False
        except RuntimeError as e:
            device.caught_errors.append(DeviceError(e))
            return False

        for _ in range(cfg.attempts):
            time.sleep(cfg.wait_before)
            try:
                output = subprocess.check_output(command, shell=use_shell).decode()
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                device.caught_errors.append(DeviceError(e))
                return False

            # For IPv6 on Windows/macOS, filter to exact IP match
            if ipv6:
                output = cls._filter_lines_by_ip(output, device.ip)

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

        On Linux, prefers 'ip neigh show' (iproute2) but falls back to
        'arp -n' (net-tools) if ip command is not available.

        Returns:
            list[str]: The ARP command to execute.
        """
        return get_arp_cache_command()

    @classmethod
    def _extract_mac_address(cls, arp_resp: str) -> List[str]:
        """Extract MAC addresses from ARP output."""
        return extract_mac_from_output(arp_resp)

    @staticmethod
    def _filter_lines_by_ip(output: str, target_ip: str) -> str:
        """Filter neighbor table output to lines containing exact IP match."""
        import ipaddress
        try:
            target_addr = ipaddress.ip_address(target_ip.split('%')[0])
        except ValueError:
            return output

        matching_lines = []
        for line in output.splitlines():
            for word in line.split():
                word_clean = word.split('%')[0].rstrip(',')
                try:
                    addr = ipaddress.ip_address(word_clean)
                    if addr == target_addr:
                        matching_lines.append(line)
                        break
                except ValueError:
                    continue
        return '\n'.join(matching_lines)


class ArpLookup():
    """
    Class to handle ARP lookups for device presence.
    NOTE: This lookup method requires elevated privileges to access the ARP cache.
    ARP is IPv4-only; IPv6 targets are skipped.

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
        if is_ipv6(device.ip):
            return device.alive is True

        enforcer_timeout = cfg.timeout * 2

        @timeout_enforcer(enforcer_timeout, raise_on_timeout=True)
        def do_arp_lookup():
            answered, _ = send_arp_request(device.ip, timeout=cfg.timeout)
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
            family = get_socket_family(device.ip)
            for i in range(cfg.attempts):
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(cfg.timeout)
                port = common_ports[i % len(common_ports)]
                sock.connect_ex((device.ip, port))
                sock.close()

        do_poke()
