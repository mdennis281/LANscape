"""
WebSocket handler for debug utilities.

Provides handlers for:
- Job statistics retrieval and reset
- ARP/NDP cache clearing
"""

import shutil
import subprocess
from typing import Any, Callable, List, Optional

import psutil

from lanscape.core.decorators import JobStats
from lanscape.ui.ws.handlers.base import BaseHandler


def _get_flush_commands(want_v6: bool) -> List[List[str]]:
    """Return OS-appropriate commands for flushing the ARP or NDP cache."""
    if psutil.WINDOWS:
        if want_v6:
            netsh_args = 'interface ipv6 delete neighbors'
        else:
            netsh_args = 'interface ipv4 delete arpcache'
        return [
            ['powershell', '-NoProfile', '-Command',
             f"Start-Process netsh -ArgumentList '{netsh_args}' "
             f"-Verb RunAs -Wait -WindowStyle Hidden"],
        ]

    if psutil.LINUX:
        if want_v6:
            cmds: list[list[str]] = []
            if shutil.which('ip'):
                cmds.append(['ip', '-6', 'neigh', 'flush', 'all'])
            return cmds
        cmds = []
        if shutil.which('ip'):
            cmds.append(['ip', '-4', 'neigh', 'flush', 'all'])
        return cmds

    if psutil.MACOS:
        if want_v6:
            return [['ndp', '-c']]
        return [['arp', '-a', '-d']]

    return []


def _run_flush(want_v6: bool) -> dict:
    """Execute flush commands and return a result dict with success/error info."""
    commands = _get_flush_commands(want_v6)
    label = 'NDP' if want_v6 else 'ARP'

    if not commands:
        return {
            'success': False,
            'error': f'No {label} flush command available for this platform',
        }

    errors: list[str] = []
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=10,
                check=False,
            )
            if result.returncode == 0:
                return {'success': True}
            stderr = result.stderr.decode(errors='replace').strip()
            errors.append(f"{' '.join(cmd)}: exit {result.returncode}"
                          + (f" — {stderr}" if stderr else ""))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            errors.append(f"{' '.join(cmd)}: {exc}")

    return {
        'success': False,
        'error': f'All {label} flush commands failed',
        'details': errors,
    }


class DebugHandler(BaseHandler):
    """
    Handler for debug WebSocket actions.

    Supports actions:
    - debug.job_stats: Get current job statistics
    - debug.job_stats_reset: Reset all job statistics
    - debug.clear_arp: Flush the IPv4 ARP cache
    - debug.clear_ndp: Flush the IPv6 NDP cache
    """

    def __init__(self):
        """Initialize the debug handler."""
        super().__init__()

        # Register handlers
        self.register('job_stats', self._handle_job_stats)
        self.register('job_stats_reset', self._handle_job_stats_reset)
        self.register('clear_arp', self._handle_clear_arp)
        self.register('clear_ndp', self._handle_clear_ndp)

    @property
    def prefix(self) -> str:
        """Return the action prefix for this handler."""
        return 'debug'

    def _handle_job_stats(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get current job statistics.

        Returns:
            Dict with 'running', 'finished', and 'timing' fields
        """
        job_stats = JobStats()
        return job_stats.get_stats_copy()

    def _handle_job_stats_reset(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Reset all job statistics.

        Returns:
            Dict with 'success' boolean
        """
        job_stats = JobStats()
        job_stats.clear_stats()
        return {'success': True}

    def _handle_clear_arp(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """Flush the system IPv4 ARP cache."""
        return _run_flush(want_v6=False)

    def _handle_clear_ndp(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """Flush the system IPv6 NDP cache."""
        return _run_flush(want_v6=True)
