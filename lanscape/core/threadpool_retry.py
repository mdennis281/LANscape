"""
ThreadPool retry manager for resilient concurrent operations.

Provides a wrapper around ThreadPoolExecutor that handles:
- Automatic retry of failed jobs with configurable retry count
- Dynamic thread count reduction on failures (via multiplier)
- Debouncing of multiplier reduction to prevent rapid decreases
- Failed jobs are requeued to the back of the work queue
"""

import logging
import traceback
from time import time
from dataclasses import dataclass, field
from typing import Callable, Any, Dict, List, TypeVar, Generic, Optional
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from threading import Lock


T = TypeVar('T')  # Return type of the job function


@dataclass
class RetryJob(Generic[T]):
    """Represents a job that can be retried."""
    job_id: Any  # Unique identifier for the job (e.g., IP address, device)
    func: Callable[..., T]
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 2

    def execute(self) -> T:
        """Execute the job function with its arguments."""
        return self.func(*self.args, **self.kwargs)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 2
    multiplier_decrease: float = 0.25
    debounce_sec: float = 5.0
    min_multiplier: float = 0.1  # Don't let multiplier go below 10%


class MultiplierController:
    """
    Controls the thread multiplier with debounced reduction on failures.

    Thread-safe controller that reduces the multiplier when failures occur,
    but debounces rapid reductions to prevent over-correction.
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        initial_multiplier: float = 1.0,
        decrease_percent: float = 0.25,
        debounce_sec: float = 5.0,
        min_multiplier: float = 0.1,
        on_warning: Optional[Callable[[str, dict], None]] = None
    ):
        self._multiplier = initial_multiplier
        self._initial_multiplier = initial_multiplier
        self._decrease_percent = decrease_percent
        self._debounce_sec = debounce_sec
        self._min_multiplier = min_multiplier
        self._last_decrease_time: float = 0.0
        self._on_warning = on_warning
        self._lock = Lock()
        self._log = logging.getLogger('MultiplierController')

    @property
    def multiplier(self) -> float:
        """Get the current multiplier value."""
        with self._lock:
            return self._multiplier

    def on_failure(self) -> bool:
        """
        Handle a failure event, potentially reducing the multiplier.

        Returns:
            bool: True if multiplier was reduced, False if debounced
        """
        with self._lock:
            current_time = time()
            time_since_last = current_time - self._last_decrease_time

            if time_since_last < self._debounce_sec:
                self._log.debug(
                    f'Multiplier decrease debounced '
                    f'({time_since_last:.1f}s < {self._debounce_sec}s)'
                )
                return False

            old_multiplier = self._multiplier
            # Reduce by the configured percentage
            self._multiplier = max(
                self._min_multiplier,
                self._multiplier * (1 - self._decrease_percent)
            )
            self._last_decrease_time = current_time

            warning_msg = (
                f'Thread multiplier reduced: {old_multiplier:.2f} -> {self._multiplier:.2f} '
                f'(decrease: {self._decrease_percent * 100:.0f}%)'
            )
            self._log.warning(warning_msg)

            # Emit warning callback if provided
            if self._on_warning:
                self._on_warning('multiplier_reduced', {
                    'message': warning_msg,
                    'old_multiplier': old_multiplier,
                    'new_multiplier': self._multiplier,
                    'decrease_percent': self._decrease_percent * 100,
                    'timestamp': current_time,
                })

            return True

    def reset(self) -> None:
        """Reset the multiplier to initial value."""
        with self._lock:
            self._multiplier = self._initial_multiplier
            self._last_decrease_time = 0.0


class ThreadPoolRetryManager:
    """
    Manages a ThreadPoolExecutor with automatic retry and multiplier control.

    When jobs fail, they are requeued to the back of the work queue for retry.
    After max retries, failures trigger multiplier reduction (with debouncing).
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        max_workers: int,
        retry_config: RetryConfig,
        multiplier_controller: MultiplierController,
        thread_name_prefix: str = "RetryPool",
        on_job_error: Optional[Callable[[Any, Exception, str], None]] = None
    ):
        """
        Initialize the retry manager.

        Args:
            max_workers: Base number of worker threads
            retry_config: Configuration for retry behavior
            multiplier_controller: Shared controller for thread multiplier
            thread_name_prefix: Prefix for thread names
            on_job_error: Optional callback when a job fails permanently
                          Signature: (job_id, exception, traceback_str)
        """
        self._base_workers = max_workers
        self._retry_config = retry_config
        self._multiplier = multiplier_controller
        self._thread_prefix = thread_name_prefix
        self._on_job_error = on_job_error
        self._log = logging.getLogger('ThreadPoolRetryManager')
        self._pending_retries: List[RetryJob] = []
        self._retry_lock = Lock()

    def _get_current_workers(self) -> int:
        """Calculate current worker count based on multiplier."""
        workers = int(self._base_workers * self._multiplier.multiplier)
        return max(1, workers)  # Always at least 1 worker

    def execute_all(
        self,
        jobs: List[RetryJob[T]]
    ) -> Dict[Any, Optional[T]]:
        """
        Execute all jobs with retry support.

        Jobs that fail will be retried up to max_retries times.
        Failed jobs are requeued to the back of the work queue.

        Args:
            jobs: List of RetryJob objects to execute

        Returns:
            Dict mapping job_id to result (or None if job failed after all retries)
        """
        results: Dict[Any, Optional[T]] = {}
        work_queue = list(jobs)

        while work_queue:
            current_workers = self._get_current_workers()
            self._log.debug(
                f'Processing {len(work_queue)} jobs with {current_workers} workers'
            )

            # Process current batch
            retry_queue: List[RetryJob] = []

            with ThreadPoolExecutor(
                max_workers=current_workers,
                thread_name_prefix=self._thread_prefix
            ) as executor:
                # Submit all jobs
                future_to_job: Dict[Future, RetryJob] = {
                    executor.submit(job.execute): job
                    for job in work_queue
                }

                # Process results as they complete
                for future in as_completed(future_to_job):
                    job = future_to_job[future]
                    try:
                        result = future.result()
                        results[job.job_id] = result
                    except Exception as e:
                        self._handle_job_failure(job, e, retry_queue, results)

            # If we have retries, they become the next work queue
            if retry_queue:
                self._log.info(
                    f'Requeueing {len(retry_queue)} jobs for retry'
                )
            work_queue = retry_queue

        return results

    def _handle_job_failure(
        self,
        job: RetryJob,
        error: Exception,
        retry_queue: List[RetryJob],
        results: Dict[Any, Any]
    ) -> None:
        """Handle a failed job, potentially scheduling a retry."""
        tb_str = traceback.format_exc()

        if job.retry_count < job.max_retries:
            # Schedule for retry - goes to back of queue
            job.retry_count += 1
            retry_queue.append(job)
            self._log.warning(
                f'Job {job.job_id} failed (attempt {job.retry_count}/{job.max_retries + 1}), '
                f'requeueing. Error: {error}'
            )
            # Trigger multiplier reduction (debounced)
            self._multiplier.on_failure()
        else:
            # Job has exhausted retries
            self._log.error(
                f'Job {job.job_id} failed permanently after {job.max_retries + 1} attempts. '
                f'Error: {error}'
            )
            results[job.job_id] = None

            # Call error callback if provided
            if self._on_job_error:
                self._on_job_error(job.job_id, error, tb_str)


def create_retry_manager_from_config(
    scan_config: 'ScanConfig',  # Forward reference to avoid circular import
    thread_count_key: str,
    multiplier_controller: MultiplierController,
    thread_name_prefix: str = "RetryPool",
    on_job_error: Optional[Callable[[Any, Exception, str], None]] = None
) -> ThreadPoolRetryManager:
    """
    Factory function to create a ThreadPoolRetryManager from ScanConfig.

    Args:
        scan_config: The scan configuration
        thread_count_key: Key for t_cnt() method (e.g., 'isalive', 'port_scan')
        multiplier_controller: Shared multiplier controller
        thread_name_prefix: Prefix for thread names
        on_job_error: Optional callback for permanent failures

    Returns:
        Configured ThreadPoolRetryManager
    """
    retry_config = RetryConfig(
        max_retries=scan_config.failure_retry_cnt,
        multiplier_decrease=scan_config.failure_multiplier_decrease,
        debounce_sec=scan_config.failure_debounce_sec,
    )

    return ThreadPoolRetryManager(
        max_workers=scan_config.t_cnt(thread_count_key),
        retry_config=retry_config,
        multiplier_controller=multiplier_controller,
        thread_name_prefix=thread_name_prefix,
        on_job_error=on_job_error,
    )
