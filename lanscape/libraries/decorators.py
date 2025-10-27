
"""Decorators and job tracking utilities for Lanscape."""

from time import time
from dataclasses import dataclass, field
from typing import DefaultDict
from collections import defaultdict
import inspect
import functools
import concurrent.futures
import logging
import threading
from tabulate import tabulate


log = logging.getLogger(__name__)


def run_once(func):
    """Ensure a function executes only once and cache the result."""

    cache_attr = "_run_once_cache"
    ran_attr = "_run_once_ran"

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if getattr(wrapper, ran_attr, False):
            return getattr(wrapper, cache_attr)

        start = time()
        result = func(*args, **kwargs)
        elapsed = time() - start

        setattr(wrapper, cache_attr, result)
        setattr(wrapper, ran_attr, True)

        log.debug("run_once executed %s in %.4fs", func.__qualname__, elapsed)
        return result

    return wrapper


class JobStats:
    """
    Thread-safe singleton for tracking job statistics across all classes.
    Tracks statistics for job execution, including running, finished, and timing data.
    """
    
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:  # Double-checked locking
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._stats_lock = threading.RLock()
            self.running = defaultdict(int)
            self.finished = defaultdict(int) 
            self.timing = defaultdict(float)
            self._initialized = True

    def start_job(self, func_name: str):
        """Thread-safe increment of running counter."""
        with self._stats_lock:
            self.running[func_name] += 1

    def finish_job(self, func_name: str, elapsed_time: float):
        """Thread-safe update of job completion and timing."""
        with self._stats_lock:
            self.running[func_name] -= 1
            self.finished[func_name] += 1
            
            # Calculate running average
            count = self.finished[func_name]
            old_avg = self.timing[func_name]
            new_avg = (old_avg * (count - 1) + elapsed_time) / count
            self.timing[func_name] = round(new_avg, 4)
            
            # Cleanup running if zero
            if self.running[func_name] <= 0:
                self.running.pop(func_name, None)

    def clear_stats(self):
        """Clear all statistics (useful between scans)."""
        with self._stats_lock:
            self.running.clear()
            self.finished.clear() 
            self.timing.clear()

    def get_stats_copy(self) -> dict:
        """Get a thread-safe copy of current statistics."""
        with self._stats_lock:
            return {
                'running': dict(self.running),
                'finished': dict(self.finished),
                'timing': dict(self.timing)
            }

    def __str__(self):
        """Return a formatted string representation of the job statistics."""
        data = [
            [
                name,
                self.running.get(name, 0),
                self.finished.get(name, 0),
                self.timing.get(name, 0.0)
            ]
            for name in set(self.running) | set(self.finished)
        ]
        headers = ["Function", "Running", "Finished", "Avg Time (s)"]
        return tabulate(
            data,
            headers=headers,
            tablefmt="grid"
        )


class JobStatsMixin:  # pylint: disable=too-few-public-methods
    """
    Singleton mixin that provides shared job_stats property across all instances.
    """
    _job_stats = None

    @property
    def job_stats(self):
        """Return the shared JobStats instance."""
        return JobStats()


def job_tracker(func):
    """
    Decorator to track job statistics for a method,
    including running count, finished count, and average timing.
    """
    def get_fxn_src_name(func, first_arg) -> str:
        """
        Return the function name with the class name prepended if available.
        """
        qual_parts = func.__qualname__.split(".")
        
        # If function has class context (e.g., "ClassName.method_name")
        if len(qual_parts) > 1:
            cls_name = qual_parts[-2]
            
            # Check if first_arg is an instance and has the expected class name
            if first_arg is not None and hasattr(first_arg, '__class__'):
                if first_arg.__class__.__name__ == cls_name:
                    return f"{cls_name}.{func.__name__}"
        
        return func.__name__

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        """Wrap the function to update job statistics before and after execution."""
        job_stats = JobStats()
        
        # Determine function name for tracking
        if args:
            fxn = get_fxn_src_name(func, args[0])
        else:
            fxn = func.__name__

        # Start job tracking
        job_stats.start_job(fxn)
        start = time()

        try:
            result = func(*args, **kwargs)  # Execute the wrapped function
            return result
        finally:
            # Always update statistics, even if function raises exception
            elapsed = time() - start
            job_stats.finish_job(fxn, elapsed)

    return wrapper


def terminator(func):
    """
    Decorator designed specifically for the SubnetScanner class,
    helps facilitate termination of a job.
    """
    def wrapper(*args, **kwargs):
        """Wrap the function to check if the scan is running before execution."""
        scan = args[0]  # aka self
        if not scan.running:
            return None
        return func(*args, **kwargs)

    return wrapper


def timeout_enforcer(timeout: int, raise_on_timeout: bool = True):
    """
    Decorator to enforce a timeout on a function.

    Args:
        timeout (int): Timeout length in seconds.
        raise_on_timeout (bool): Whether to raise an exception if the timeout is exceeded.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            """Wrap the function to enforce a timeout on its execution."""
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix="TimeoutEnforcer") as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(
                        timeout=timeout
                    )
                except concurrent.futures.TimeoutError as exc:
                    if raise_on_timeout:
                        raise TimeoutError(
                            f"Function '{func.__name__}' exceeded timeout of "
                            f"{timeout} seconds."
                        ) from exc
                    return None  # Return None if not raising an exception
        return wrapper
    return decorator
