"""
WebSocket handler for network scanning operations.

Provides handlers for:
- Starting scans (threaded and synchronous)
- Getting scan results (full and delta)
- Getting scan summary/status
- Terminating scans
- Subscribing to real-time scan updates
"""

import asyncio
import logging
from typing import Any, Callable, Optional

from lanscape.core.subnet_scan import ScanManager, ScanConfig
from lanscape.ui.ws.handlers.base import BaseHandler
from lanscape.ui.ws.delta import ScanDeltaTracker


class ScanHandler(BaseHandler):
    """
    Handler for scan-related WebSocket actions.

    Supports actions:
    - scan.start: Start a new scan (non-blocking)
    - scan.start_sync: Start a scan and wait for completion
    - scan.get: Get full scan results
    - scan.get_delta: Get only changed results since last request
    - scan.summary: Get scan summary/progress
    - scan.terminate: Stop a running scan
    - scan.subscribe: Subscribe to real-time scan updates
    - scan.unsubscribe: Unsubscribe from scan updates
    """

    def __init__(self, scan_manager: Optional[ScanManager] = None):
        """
        Initialize the scan handler.

        Args:
            scan_manager: Optional ScanManager instance. If not provided,
                         uses the singleton instance.
        """
        super().__init__()
        self._scan_manager = scan_manager or ScanManager()
        self._delta_trackers: dict[str, ScanDeltaTracker] = {}
        self._subscriptions: dict[str, set] = {}  # scan_id -> set of client_ids
        self.log = logging.getLogger('ScanHandler')

        # Register handlers
        self.register('start', self._handle_start)
        self.register('start_sync', self._handle_start_sync)
        self.register('get', self._handle_get)
        self.register('get_delta', self._handle_get_delta)
        self.register('summary', self._handle_summary)
        self.register('terminate', self._handle_terminate)
        self.register('subscribe', self._handle_subscribe)
        self.register('unsubscribe', self._handle_unsubscribe)
        self.register('list', self._handle_list)

    @property
    def prefix(self) -> str:
        """Return the action prefix for this handler."""
        return 'scan'

    def _handle_start(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Start a new network scan.

        Params:
            subnet: Target subnet to scan
            port_list: Name of the port list to use
            ... (other ScanConfig parameters)

        Returns:
            Dict with scan_id and status
        """
        config = ScanConfig.from_dict(params)
        scan = self._scan_manager.new_scan(config)
        self.log.info(f"Started scan {scan.uid} for {config.subnet}")

        return {
            'scan_id': scan.uid,
            'status': 'running'
        }

    async def _handle_start_sync(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Start a scan and wait for completion.

        Params:
            Same as _handle_start

        Returns:
            Dict with scan_id and status='complete'
        """
        config = ScanConfig.from_dict(params)
        scan = self._scan_manager.new_scan(config)
        self.log.info(f"Started sync scan {scan.uid} for {config.subnet}")

        # Wait for completion in a non-blocking way
        while scan.running:
            await asyncio.sleep(0.5)

        return {
            'scan_id': scan.uid,
            'status': 'complete'
        }

    def _handle_get(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get full scan results.

        Params:
            scan_id: The scan ID to retrieve

        Returns:
            Full scan results as dict
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        scan = self._scan_manager.get_scan(scan_id)

        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        return scan.results.to_results().model_dump(mode='json')

    def _handle_get_delta(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get only changed scan results since last request.

        Params:
            scan_id: The scan ID to retrieve
            client_id: Client identifier for tracking deltas

        Returns:
            Delta update containing only changed devices and metadata
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        client_id = self._get_param(params, 'client_id', default='default')

        scan = self._scan_manager.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        # Get or create delta tracker for this client
        tracker_key = f"{scan_id}_{client_id}"
        if tracker_key not in self._delta_trackers:
            self._delta_trackers[tracker_key] = ScanDeltaTracker()

        tracker = self._delta_trackers[tracker_key]
        full_results = scan.results.to_results().model_dump(mode='json')
        delta = tracker.get_scan_delta(full_results)

        # Add scan status info
        delta['scan_id'] = scan_id
        delta['running'] = scan.running

        # Add calculated progress from backend (more accurate than simple host count)
        if delta.get('metadata') is None:
            delta['metadata'] = {}
        delta['metadata']['percent_complete'] = scan.calc_percent_complete()

        return delta

    def _handle_summary(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Get scan summary/progress.

        Params:
            scan_id: The scan ID to get summary for

        Returns:
            Dict with running status, percent complete, stage, runtime, and device counts
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        scan = self._scan_manager.get_scan(scan_id)

        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        return scan.results.to_summary().model_dump(mode='json')

    def _handle_terminate(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Terminate a running scan.

        Params:
            scan_id: The scan ID to terminate

        Returns:
            Dict with success status
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        scan = self._scan_manager.get_scan(scan_id)

        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        scan.terminate()
        self.log.info(f"Terminated scan {scan_id}")

        return {'success': True, 'scan_id': scan_id}

    def _handle_subscribe(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Subscribe to real-time scan updates.

        Params:
            scan_id: The scan ID to subscribe to
            client_id: Client identifier for the subscription

        Returns:
            Dict with subscription confirmation
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        client_id = self._get_param(params, 'client_id', required=True)

        scan = self._scan_manager.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        if scan_id not in self._subscriptions:
            self._subscriptions[scan_id] = set()
        self._subscriptions[scan_id].add(client_id)

        self.log.debug(f"Client {client_id} subscribed to scan {scan_id}")

        return {
            'subscribed': True,
            'scan_id': scan_id,
            'client_id': client_id
        }

    def _handle_unsubscribe(
        self,
        params: dict[str, Any],
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> dict:
        """
        Unsubscribe from scan updates.

        Params:
            scan_id: The scan ID to unsubscribe from
            client_id: Client identifier for the subscription

        Returns:
            Dict with unsubscription confirmation
        """
        scan_id = self._get_param(params, 'scan_id', required=True)
        client_id = self._get_param(params, 'client_id', required=True)

        if scan_id in self._subscriptions:
            self._subscriptions[scan_id].discard(client_id)

        # Clean up delta tracker
        tracker_key = f"{scan_id}_{client_id}"
        self._delta_trackers.pop(tracker_key, None)

        self.log.debug(f"Client {client_id} unsubscribed from scan {scan_id}")

        return {
            'unsubscribed': True,
            'scan_id': scan_id,
            'client_id': client_id
        }

    def _handle_list(
        self,
        params: dict[str, Any],  # pylint: disable=unused-argument
        send_event: Optional[Callable] = None  # pylint: disable=unused-argument
    ) -> list:
        """
        List all scans.

        Returns:
            List of scan summaries
        """
        return [
            scan.results.to_list_item().model_dump(mode='json')
            for scan in self._scan_manager.scans
        ]

    def get_subscriptions(self, scan_id: str) -> set:
        """
        Get all client IDs subscribed to a scan.

        Args:
            scan_id: The scan ID

        Returns:
            Set of client IDs
        """
        return self._subscriptions.get(scan_id, set())

    def cleanup_client(self, client_id: str) -> None:
        """
        Clean up all subscriptions for a client.

        Args:
            client_id: The client ID to clean up
        """
        for scan_id in list(self._subscriptions.keys()):
            self._subscriptions[scan_id].discard(client_id)
            tracker_key = f"{scan_id}_{client_id}"
            self._delta_trackers.pop(tracker_key, None)
