"""Tests for helper decorators used throughout the project."""

import logging

from lanscape.libraries.decorators import run_once


def test_run_once_caches_result_and_logs_once(caplog):
    """run_once should execute only one time and cache the return value."""

    caplog.set_level(logging.DEBUG)

    call_count = {"count": 0}

    @run_once
    def sample_function(value):
        call_count["count"] += 1
        return value * 2

    first = sample_function(3)
    second = sample_function(5)

    assert first == 6
    assert second == 6
    assert call_count["count"] == 1

    messages = [record.message for record in caplog.records]
    assert any("run_once executed" in record and "sample_function" in record for record in messages)
    assert sum("run_once executed" in record for record in messages) == 1

