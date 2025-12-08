"""Reliability scan queue for orchestrating sequential test runs."""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from lanscape.core.scan_config import ScanConfig
from lanscape.core.subnet_scan import ScanManager, SubnetScanner


@dataclass
class ReliabilityJob:
    """Represents a queued reliability scan request."""

    id: str
    config: ScanConfig
    label: str
    status: str = 'queued'
    scan_id: Optional[str] = None
    enqueued_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None
    result_snapshot: Optional[dict] = None

    def summary(self) -> dict:
        """Return a serializable summary of the job."""
        base = {
            'id': self.id,
            'label': self.label,
            'status': self.status,
            'scan_id': self.scan_id,
            'enqueued_at': self.enqueued_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'error': self.error,
            'config': self.config.to_dict(),
        }
        if self.result_snapshot:
            base['snapshot'] = self.result_snapshot
        return base


class ReliabilityQueue:
    """FIFO queue that ensures only one scan runs at a time."""

    _instance: Optional['ReliabilityQueue'] = None

    def __new__(cls) -> 'ReliabilityQueue':
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return

        self.scan_manager = ScanManager()
        self._jobs: Dict[str, ReliabilityJob] = {}
        self._queue: Deque[str] = deque()
        self._lock = threading.RLock()
        self._has_items = threading.Condition(self._lock)
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()
        self._initialized = True

    # Public API -----------------------------------------------------------------

    def enqueue(self, config: ScanConfig, label: Optional[str] = None, repeat: int = 1) -> List[ReliabilityJob]:
        """Queue one or more scans for sequential execution."""
        created: List[ReliabilityJob] = []
        count = max(1, repeat)
        with self._has_items:
            for _ in range(count):
                job_id = str(uuid.uuid4())
                job_label = label or f"Run {job_id[:8]}"
                # ensure each job has its own config instance
                job_config = config.model_copy(deep=True)
                job = ReliabilityJob(id=job_id, config=job_config, label=job_label)
                self._jobs[job_id] = job
                self._queue.append(job_id)
                created.append(job)
            self._has_items.notify()
        return created

    def list_jobs(self) -> List[dict]:
        """Return all jobs ordered by enqueue time."""
        with self._lock:
            jobs = [self._serialize_job(job) for job in sorted(
                self._jobs.values(), key=lambda item: item.enqueued_at)]
        return jobs

    def get_job(self, job_id: str) -> Optional[dict]:
        """Return a job summary by id."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return self._serialize_job(job)

    def cancel(self, job_id: str) -> bool:
        """Cancel a queued job if it has not started."""
        with self._has_items:
            job = self._jobs.get(job_id)
            if not job or job.status != 'queued':
                return False
            try:
                self._queue.remove(job_id)
            except ValueError:
                return False
            job.status = 'cancelled'
            job.completed_at = time.time()
            self._jobs[job_id] = job
            return True

    def get_status_counts(self) -> Dict[str, int]:
        """Return aggregate counts for each job status."""
        with self._lock:
            summary: Dict[str, int] = {
                'queued': 0,
                'running': 0,
                'completed': 0,
                'errors': 0,
                'cancelled': 0
            }
            for job in self._jobs.values():
                status = job.status or 'queued'
                if status == 'error':
                    summary['errors'] += 1
                elif status in summary:
                    summary[status] += 1
                else:
                    summary[status] = summary.get(status, 0) + 1
            return summary

    # Internal helpers -----------------------------------------------------------

    def _worker_loop(self) -> None:
        while True:
            with self._has_items:
                while not self._queue:
                    self._has_items.wait()
                job_id = self._queue[0]
                job = self._jobs.get(job_id)
                if not job:
                    self._queue.popleft()
                    continue
                if job.status != 'queued':
                    self._queue.popleft()
                    continue
                job.status = 'running'
                job.started_at = time.time()

            try:
                scan = self._start_scan(job)
                self.scan_manager.wait_until_complete(scan.uid)
                snapshot = self._snapshot_scan(scan)
                with self._lock:
                    job.status = 'completed'
                    job.completed_at = time.time()
                    job.result_snapshot = snapshot
                    self._queue.popleft()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                with self._lock:
                    job.status = 'error'
                    job.error = str(exc)
                    job.completed_at = time.time()
                    if self._queue and self._queue[0] == job.id:
                        self._queue.popleft()

    def _start_scan(self, job: ReliabilityJob) -> SubnetScanner:
        scan = self.scan_manager.new_scan(job.config)
        job.scan_id = scan.uid
        return scan

    def _serialize_job(self, job: ReliabilityJob) -> dict:
        payload = job.summary()
        payload['queue_position'] = self._queue_position(job.id)
        payload['snapshot'] = self._live_snapshot(job)
        return payload

    def _queue_position(self, job_id: str) -> Optional[int]:
        try:
            position = list(self._queue).index(job_id)
            return position
        except ValueError:
            return None

    def _live_snapshot(self, job: ReliabilityJob) -> Optional[dict]:
        if job.result_snapshot:
            return job.result_snapshot
        if not job.scan_id:
            return None
        scan = self.scan_manager.get_scan(job.scan_id)
        if not scan:
            return None
        return self._snapshot_scan(scan)

    def _snapshot_scan(self, scan: SubnetScanner) -> dict:
        devices = scan.results.devices
        open_ports = sum(len(getattr(device, 'ports', [])) for device in devices)
        snapshot = {
            'running': scan.running,
            'percent_complete': scan.calc_percent_complete(),
            'stage': scan.results.stage,
            'runtime': scan.results.get_runtime(),
            'devices': {
                'alive': len(devices),
                'scanned': scan.results.devices_scanned,
                'total': scan.results.devices_total,
            },
            'open_ports': open_ports,
            'scan_id': scan.uid,
        }
        return snapshot


reliability_queue = ReliabilityQueue()
