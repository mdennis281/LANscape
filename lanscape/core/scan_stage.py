"""Base class for composable scan stages with standardized progress tracking."""

import logging
import threading
from abc import ABC, abstractmethod
from time import time
from typing import TYPE_CHECKING, Optional

from lanscape.core.models.enums import StageType
from lanscape.core.models.scan import StageEvalContext, StageProgress

if TYPE_CHECKING:
    from lanscape.core.scan_context import ScanContext


class ScanStageMixin(ABC):
    """Abstract base for all scan stages.

    Provides standardized progress IO (``total``, ``completed``, ``finished``)
    and a thread-safe ``increment()`` helper.  Concrete stages must implement
    :meth:`execute` which receives the shared :class:`ScanContext`.
    """

    stage_type: StageType
    stage_name: str
    counter_label: str = "items"

    def __init__(self) -> None:
        self._total: int = 0
        self._completed: int = 0
        self._finished: bool = False
        self._skipped: bool = False
        self._skip_reason: Optional[str] = None
        self.running: bool = False
        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._end_time: float = 0.0
        self.log = logging.getLogger(self.__class__.__name__)
        self.auto: Optional[bool] = None
        self.reason: Optional[str] = None

    # ── Progress properties ─────────────────────────────────────────

    @property
    def total(self) -> int:
        """Return the total number of work items."""
        return self._total

    @total.setter
    def total(self, value: int) -> None:
        with self._lock:
            self._total = value

    @property
    def completed(self) -> int:
        """Return the number of completed work items."""
        return self._completed

    @property
    def finished(self) -> bool:
        """Return whether the stage has finished executing."""
        return self._finished

    def increment(self) -> None:
        """Thread-safe increment of the completed counter."""
        with self._lock:
            self._completed += 1

    @property
    def runtime(self) -> float:
        """Return elapsed seconds for this stage."""
        if self._start_time == 0.0:
            return 0.0
        end = self._end_time if self._finished else time()
        return round(end - self._start_time, 1)

    def stage_progress(self) -> StageProgress:
        """Return an immutable snapshot of current progress."""
        return StageProgress(
            stage_name=self.stage_name,
            stage_type=self.stage_type,
            total=self._total,
            completed=self._completed,
            finished=self._finished,
            skipped=self._skipped,
            skip_reason=self._skip_reason,
            runtime=self.runtime,
            counter_label=self.counter_label,
            auto=self.auto,
            reason=self.reason,
        )

    # ── Skip guard ──────────────────────────────────────────────────

    def can_execute(self, _eval_ctx: StageEvalContext) -> Optional[str]:
        """Return ``None`` if the stage can run, or a reason string to skip.

        Subclasses override this to enforce pre-conditions (e.g. IPv4-only,
        local subnet required).  The default implementation always allows
        execution.
        """
        return None

    def mark_skipped(self, reason: str) -> None:
        """Mark this stage as skipped without executing it."""
        self._finished = True
        self._skipped = True
        self._skip_reason = reason

    # ── Lifecycle ───────────────────────────────────────────────────

    def run(self, context: 'ScanContext') -> None:
        """Entry-point called by :class:`ScanPipeline`.

        Wraps :meth:`execute` with pre/post bookkeeping.
        """
        self.running = True
        self._finished = False
        self._start_time = time()
        try:
            self.execute(context)
        finally:
            self._end_time = time()
            self.running = False
            self._finished = True

    @abstractmethod
    def execute(self, context: 'ScanContext') -> None:
        """Perform the stage's work.  Must be implemented by subclasses."""

    def terminate(self) -> None:
        """Request graceful termination of the stage."""
        self.running = False
