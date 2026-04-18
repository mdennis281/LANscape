"""Sequential pipeline orchestrator for composable scan stages."""

import logging
from typing import Callable, List, Optional

from lanscape.core.scan_stage import ScanStageMixin
from lanscape.core.scan_context import ScanContext
from lanscape.core.models.scan import StageProgress


log = logging.getLogger(__name__)


class ScanPipeline:
    """Execute an ordered list of :class:`ScanStageMixin` stages.

    Stages are run sequentially.  The interface is designed to support
    parallel execution in the future, but the current implementation is
    strictly sequential.
    """

    def __init__(
        self,
        stages: List[ScanStageMixin],
        on_stage_change: Optional[Callable[[ScanStageMixin], None]] = None,
    ) -> None:
        self.stages = stages
        self._current_index: Optional[int] = None
        self._terminated: bool = False
        self._on_stage_change = on_stage_change

    # ── Execution ───────────────────────────────────────────────────

    def execute(self, context: ScanContext) -> None:
        """Run each stage in order, passing the shared *context*.

        Uses index-based iteration so stages appended after execution
        starts are automatically picked up.  Stages that have already
        finished (e.g. from a prior run) are skipped so that a restart
        only executes newly-appended stages.
        """
        idx = 0
        while idx < len(self.stages):
            if self._terminated:
                log.info("Pipeline terminated — skipping remaining stages")
                break

            stage = self.stages[idx]

            # Skip stages that already completed in a previous run
            if stage.finished:
                idx += 1
                continue

            self._current_index = idx
            log.info(
                "Pipeline stage %d/%d: %s",
                idx + 1, len(self.stages), stage.stage_name,
            )
            if self._on_stage_change:
                self._on_stage_change(stage)
            stage.run(context)

            # After every discovery stage, consolidate devices that
            # share a hostname or MAC into a single entry.
            if stage.stage_type.value.endswith("_discovery"):
                merged = context.consolidate_devices()
                if merged:
                    log.info("Consolidated %d duplicate device(s)", merged)

            idx += 1

        self._current_index = None

    # ── Termination ─────────────────────────────────────────────────

    def terminate(self) -> None:
        """Terminate the current stage and skip all remaining stages."""
        self._terminated = True
        current = self.current_stage
        if current is not None:
            current.terminate()

    # ── Mutation ────────────────────────────────────────────────────

    def append_stages(self, new_stages: List[ScanStageMixin]) -> None:
        """Append stages to the pipeline.

        If the pipeline has already finished (or was terminated), reset
        the terminated flag so a subsequent :meth:`execute` call will
        pick up the new stages.
        """
        self.stages.extend(new_stages)
        if self._terminated:
            self._terminated = False

    def update_stage(self, index: int, new_stage: ScanStageMixin) -> None:
        """Replace a future stage that has not yet started.

        Only stages that are pending (not currently running or finished)
        may be replaced.  Raises :class:`ValueError` for invalid indices
        or stages that cannot be swapped.
        """
        if index < 0 or index >= len(self.stages):
            raise ValueError(
                f"Stage index {index} out of range (0–{len(self.stages) - 1})"
            )

        if self._current_index is not None and index <= self._current_index:
            raise ValueError(
                f"Cannot update stage {index}: it is currently running or already finished"
            )

        existing = self.stages[index]
        if existing.finished:
            raise ValueError(
                f"Cannot update stage {index}: it has already finished"
            )

        log.info("Replacing pipeline stage %d (%s → %s)",
                 index, existing.stage_name, new_stage.stage_name)
        self.stages[index] = new_stage

    # ── Progress ────────────────────────────────────────────────────

    @property
    def current_stage(self) -> Optional[ScanStageMixin]:
        """Return the currently executing stage, or None."""
        if self._current_index is not None and self._current_index < len(self.stages):
            return self.stages[self._current_index]
        return None

    @property
    def current_stage_index(self) -> Optional[int]:
        """Return the index of the currently executing stage."""
        return self._current_index

    def get_stage_progress(self) -> List[StageProgress]:
        """Return progress snapshots for every stage in the pipeline."""
        return [s.stage_progress() for s in self.stages]
