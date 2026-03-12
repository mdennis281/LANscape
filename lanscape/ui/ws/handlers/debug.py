"""
WebSocket handler for debug utilities.

Provides handlers for:
- Job statistics retrieval and reset
"""

from typing import Any, Callable, Optional

from lanscape.core.decorators import JobStats
from lanscape.ui.ws.handlers.base import BaseHandler


class DebugHandler(BaseHandler):
    """
    Handler for debug WebSocket actions.

    Supports actions:
    - debug.job_stats: Get current job statistics
    - debug.job_stats_reset: Reset all job statistics
    """

    def __init__(self):
        """Initialize the debug handler."""
        super().__init__()

        # Register handlers
        self.register('job_stats', self._handle_job_stats)
        self.register('job_stats_reset', self._handle_job_stats_reset)

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
