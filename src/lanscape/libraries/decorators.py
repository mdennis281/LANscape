from time import time
from dataclasses import dataclass, field
from typing import DefaultDict
from collections import defaultdict
from tabulate import tabulate
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


def job_tracker(func):
    fxn = func.__name__

    def wrapper(*args, **kwargs):
        # Access the class instance and initialize job tracking stats
        class_instance = args[0]
        job_stats = init_job_tracker(class_instance)

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

    def init_job_tracker(class_instance):
        # Initialize job_stats if it doesn't exist
        if not hasattr(class_instance, 'job_stats'):
            class_instance.job_stats = JobStats()
        return class_instance.job_stats

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
    