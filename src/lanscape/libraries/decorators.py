from time import time
from dataclasses import dataclass, field
from typing import DefaultDict
from collections import defaultdict
from tabulate import tabulate
import inspect
import threading
import functools
import concurrent.futures

@dataclass
class JobStats:
    running: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    finished: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    timing: DefaultDict[str, float] = field(default_factory=lambda: defaultdict(float))

    def __str__(self):
        data = [
            [name, self.running.get(name, 0), self.finished.get(name, 0), self.timing.get(name, 0.0)]
            for name in set(self.running) | set(self.finished)
        ]

        headers = ["Function", "Running", "Finished", "Avg Time (s)"]
        return tabulate(data, headers=headers, tablefmt="grid")


class JobStatsMixin:
    """Singleton mixin that provides shared job_stats property across all instances"""
    _job_stats = None
    
    @property
    def job_stats(self):
        if JobStatsMixin._job_stats is None:
            JobStatsMixin._job_stats = JobStats()
        return JobStatsMixin._job_stats


def job_tracker(func):


    def get_fxn_src_name(func, first_arg) -> str:
        """
        first_arg ideally is the class instance,
        this will return the function name with the class name prepended
        """
        qual_parts = func.__qualname__.split(".")
        cls_name   = qual_parts[-2] if len(qual_parts) > 1 else None
        cls_obj    = None                     # resolved lazily
        if cls_obj is None and cls_name:
            mod = inspect.getmodule(func)
            cls_obj = getattr(mod, cls_name, None)
        if cls_obj and first_arg is not None:
            if (first_arg is cls_obj or isinstance(first_arg, cls_obj)):
                return f"{cls_name}.{func.__name__}"
        return func.__name__


    def wrapper(*args, **kwargs):
        # Access the class instance and get job tracking stats
        class_instance = args[0]
        job_stats = class_instance.job_stats
        fxn = get_fxn_src_name(func, class_instance)

        # Increment running counter and track execution time
        job_stats.running[fxn] += 1
        start = time()
        
        result = func(*args, **kwargs)  # Execute the wrapped function
        
        # Update statistics after function execution
        elapsed = time() - start
        job_stats.running[fxn] -= 1
        job_stats.finished[fxn] += 1

        # Calculate the new average timing for the function
        job_stats.timing[fxn] = round(
            ((job_stats.finished[fxn] - 1) * job_stats.timing[fxn] + elapsed) / job_stats.finished[fxn], 4
        )

        # Clean up if no more running instances of this function
        if job_stats.running[fxn] == 0:
            job_stats.running.pop(fxn)

        return result

    return wrapper


def terminator(func):
    """
    decorator designed specifically for the SubnetScanner class,
    helps facilitate termination of a job
    """
    def wrapper(*args, **kwargs):
        scan = args[0] # aka self
        if not scan.running:
            return
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    if raise_on_timeout:
                        raise TimeoutError(f"Function '{func.__name__}' exceeded timeout of {timeout} seconds.")
                    return None  # Return None if not raising an exception
        return wrapper
    return decorator
