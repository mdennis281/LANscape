"""System and process metrics used by the reliability dashboard."""

from __future__ import annotations

import threading
from typing import Dict, Optional

import psutil

_PROCESS = psutil.Process()
# Warm up CPU percent trackers so subsequent reads are relative deltas.
psutil.cpu_percent(interval=None)
_PROCESS.cpu_percent(interval=None)
_CPU_LOCK = threading.Lock()
SYSTEM_CPU_INTERVAL = 1.0  # seconds
PROCESS_CPU_INTERVAL = 0.1


def _bytes_to_mb(value: float) -> float:
    return round(value / (1024 ** 2), 1)


def _bytes_to_gb(value: float) -> float:
    return round(value / (1024 ** 3), 2)


def collect_runtime_metrics(extra: Optional[Dict[str, Dict[str, int]]] = None) -> Dict:
    """Gather CPU, memory, and threading metrics.

    Args:
        extra: Optional dictionary of additional metric groups to merge.

    Returns:
        Dictionary suited for JSON responses.
    """
    with _CPU_LOCK:
        system_percent = psutil.cpu_percent(interval=SYSTEM_CPU_INTERVAL)
        process_percent = _PROCESS.cpu_percent(interval=PROCESS_CPU_INTERVAL)

    virtual_memory = psutil.virtual_memory()

    process_mem = _PROCESS.memory_info().rss

    metrics = {
        'threads': {
            'process': _PROCESS.num_threads(),
            'python': threading.active_count(),
        },
        'cpu': {
            'system_percent': round(system_percent, 1),
            'process_percent': round(process_percent, 1),
        },
        'memory': {
            'system_percent': round(virtual_memory.percent, 1),
            'system_used_gb': _bytes_to_gb(virtual_memory.used),
            'system_total_gb': _bytes_to_gb(virtual_memory.total),
            'process_mb': _bytes_to_mb(process_mem),
            'process_percent': round(
                (process_mem / virtual_memory.total) * 100, 2
            ) if virtual_memory.total else 0.0,
        }
    }

    if extra:
        metrics.update(extra)

    return metrics
