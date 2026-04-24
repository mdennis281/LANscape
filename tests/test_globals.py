"""DEPRECATED: constants moved to tests/_helpers.py. This shim preserves
backward-compat imports. Safe to delete once no callers reference
`tests.test_globals` directly.
"""
from tests._helpers import (  # noqa: F401
    TEST_SUBNET,
    MIN_EXPECTED_RUNTIME,
    MIN_EXPECTED_ALIVE_DEVICES,
)
