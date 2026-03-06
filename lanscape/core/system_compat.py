"""
System compatibility utilities.

Provides cross-platform detection and fallback logic for system commands
and capabilities that vary across operating systems.
"""

import logging
import shutil
from typing import List, Tuple

import psutil

from lanscape.core.decorators import run_once


log = logging.getLogger(__name__)


@run_once
def get_linux_arp_command() -> Tuple[List[str], str]:
    """
    Get the ARP cache command for Linux, with fallback.

    Prefers 'ip neigh show' (iproute2) but falls back to 'arp -n'
    (net-tools) if ip command is not available. Result is cached via @run_once.

    Returns:
        Tuple of:
        - list[str]: Command as list for subprocess (e.g., ['ip', 'neigh', 'show'])
        - str: Command as string for shell execution (e.g., 'ip neigh show')
    """
    # Prefer iproute2 (modern Linux), fall back to net-tools (legacy)
    if shutil.which('ip'):
        return (['ip', 'neigh', 'show'], 'ip neigh show')

    if shutil.which('arp'):
        return (['arp', '-n'], 'arp -n')

    # Neither available - return ip and let it fail with clear error
    log.warning("Neither 'ip' nor 'arp' command found - ARP lookup may fail")
    return (['ip', 'neigh', 'show'], 'ip neigh show')


def get_arp_cache_command() -> List[str]:
    """
    Get the platform-appropriate ARP cache command.

    Returns:
        list[str]: The ARP command to execute (without IP argument).
    """
    if psutil.WINDOWS:
        return ['arp', '-a']
    if psutil.LINUX:
        cmd_list, _ = get_linux_arp_command()
        return cmd_list
    if psutil.MACOS:
        return ['arp', '-n']

    raise NotImplementedError("Unsupported platform")
