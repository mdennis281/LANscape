"""
Tests for the ThreadPoolRetryManager and related classes.
"""
import pytest
from time import sleep
from unittest.mock import Mock, MagicMock, patch
from lanscape.core.threadpool_retry import (
    ThreadPoolRetryManager,
    RetryJob,
    RetryConfig,
    MultiplierController,
    create_retry_manager_from_config
)


class TestMultiplierController:
    """Tests for MultiplierController."""

    def test_initial_multiplier(self):
        """Test that initial multiplier is set correctly."""
        controller = MultiplierController(initial_multiplier=1.0)
        assert controller.multiplier == 1.0

    def test_on_failure_reduces_multiplier(self):
        """Test that on_failure reduces the multiplier."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=0.0  # No debounce for testing
        )
        result = controller.on_failure()
        assert result is True
        assert controller.multiplier == 0.75

    def test_on_failure_respects_min_multiplier(self):
        """Test that multiplier doesn't go below minimum."""
        controller = MultiplierController(
            initial_multiplier=0.15,
            decrease_percent=0.5,
            debounce_sec=0.0,
            min_multiplier=0.1
        )
        controller.on_failure()
        assert controller.multiplier >= 0.1

    def test_on_failure_debounce(self):
        """Test that rapid failures are debounced."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=1.0  # 1 second debounce
        )

        # First failure should reduce
        result1 = controller.on_failure()
        assert result1 is True
        assert controller.multiplier == 0.75

        # Second immediate failure should be debounced
        result2 = controller.on_failure()
        assert result2 is False
        assert controller.multiplier == 0.75  # Unchanged

    def test_on_failure_after_debounce_period(self):
        """Test that failures after debounce period work."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=0.1  # 100ms debounce
        )

        controller.on_failure()
        assert controller.multiplier == 0.75

        sleep(0.15)  # Wait for debounce to expire

        controller.on_failure()
        assert controller.multiplier == pytest.approx(0.5625, rel=0.01)

    def test_reset(self):
        """Test reset restores initial multiplier."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=0.0
        )
        controller.on_failure()
        assert controller.multiplier < 1.0

        controller.reset()
        assert controller.multiplier == 1.0

    def test_on_warning_callback(self):
        """Test that warning callback is called on failure."""
        warnings_received = []

        def warning_handler(warning_type: str, warning_data: dict):
            warnings_received.append((warning_type, warning_data))

        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=0.0,
            on_warning=warning_handler
        )

        controller.on_failure()

        assert len(warnings_received) == 1
        warning_type, warning_data = warnings_received[0]
        assert warning_type == 'multiplier_reduced'
        assert warning_data['old_multiplier'] == 1.0
        assert warning_data['new_multiplier'] == 0.75
        assert warning_data['decrease_percent'] == 25.0
        assert 'message' in warning_data
        assert 'timestamp' in warning_data


class TestRetryJob:
    """Tests for RetryJob."""

    def test_execute_calls_function(self):
        """Test that execute calls the wrapped function."""
        mock_func = Mock(return_value="result")
        job = RetryJob(
            job_id="test",
            func=mock_func,
            args=(1, 2),
            kwargs={"key": "value"}
        )

        result = job.execute()

        assert result == "result"
        mock_func.assert_called_once_with(1, 2, key="value")

    def test_retry_count_tracking(self):
        """Test retry count is tracked correctly."""
        job = RetryJob(
            job_id="test",
            func=lambda: None,
            max_retries=3
        )
        assert job.retry_count == 0

        job.retry_count += 1
        assert job.retry_count == 1


class TestThreadPoolRetryManager:
    """Tests for ThreadPoolRetryManager."""

    def test_successful_jobs_complete(self):
        """Test that successful jobs complete normally."""
        controller = MultiplierController(initial_multiplier=1.0, debounce_sec=0.0)
        retry_config = RetryConfig(max_retries=2)

        manager = ThreadPoolRetryManager(
            max_workers=2,
            retry_config=retry_config,
            multiplier_controller=controller,
        )

        jobs = [
            RetryJob(job_id=f"job_{i}", func=lambda x=i: x * 2, max_retries=2)
            for i in range(5)
        ]

        results = manager.execute_all(jobs)

        assert len(results) == 5
        # All jobs should have results (not None)
        for job_id, result in results.items():
            assert result is not None

    def test_failing_job_retries(self):
        """Test that failing jobs are retried."""
        controller = MultiplierController(initial_multiplier=1.0, debounce_sec=0.0)
        retry_config = RetryConfig(max_retries=2)

        call_count = 0

        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"

        manager = ThreadPoolRetryManager(
            max_workers=1,
            retry_config=retry_config,
            multiplier_controller=controller,
        )

        jobs = [RetryJob(job_id="flaky", func=flaky_func, max_retries=2)]

        results = manager.execute_all(jobs)

        # Should have called 3 times (2 failures + 1 success)
        assert call_count == 3
        assert results["flaky"] == "success"

    def test_permanent_failure_after_max_retries(self):
        """Test that jobs fail permanently after max retries."""
        controller = MultiplierController(initial_multiplier=1.0, debounce_sec=0.0)
        retry_config = RetryConfig(max_retries=2)
        error_callback = Mock()

        def always_fail():
            raise Exception("Always fails")

        manager = ThreadPoolRetryManager(
            max_workers=1,
            retry_config=retry_config,
            multiplier_controller=controller,
            on_job_error=error_callback,
        )

        jobs = [RetryJob(job_id="doomed", func=always_fail, max_retries=2)]

        results = manager.execute_all(jobs)

        # Result should be None for failed job
        assert results["doomed"] is None
        # Error callback should have been called
        error_callback.assert_called_once()

    def test_multiplier_reduced_on_failure(self):
        """Test that multiplier is reduced when jobs fail."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.25,
            debounce_sec=0.0
        )
        retry_config = RetryConfig(max_retries=1)

        def always_fail():
            raise Exception("Fail")

        manager = ThreadPoolRetryManager(
            max_workers=1,
            retry_config=retry_config,
            multiplier_controller=controller,
        )

        jobs = [RetryJob(job_id="fail", func=always_fail, max_retries=1)]

        manager.execute_all(jobs)

        # Multiplier should have been reduced
        assert controller.multiplier < 1.0

    def test_worker_count_reduces_with_multiplier(self):
        """Test that worker count is recalculated when multiplier decreases."""
        controller = MultiplierController(
            initial_multiplier=1.0,
            decrease_percent=0.5,
            debounce_sec=0.0
        )
        retry_config = RetryConfig(max_retries=0)

        manager = ThreadPoolRetryManager(
            max_workers=10,
            retry_config=retry_config,
            multiplier_controller=controller,
        )

        # Initial workers
        assert manager._get_current_workers() == 10

        # After multiplier reduction
        controller.on_failure()
        assert manager._get_current_workers() == 5

    def test_minimum_one_worker(self):
        """Test that there's always at least one worker."""
        controller = MultiplierController(
            initial_multiplier=0.01,
            decrease_percent=0.0,
            debounce_sec=0.0
        )
        retry_config = RetryConfig(max_retries=0)

        manager = ThreadPoolRetryManager(
            max_workers=2,
            retry_config=retry_config,
            multiplier_controller=controller,
        )

        # Even with very low multiplier, should have at least 1 worker
        assert manager._get_current_workers() >= 1


class TestCreateRetryManagerFromConfig:
    """Tests for the factory function."""

    def test_creates_manager_with_config_values(self):
        """Test that factory creates manager with correct config."""
        # Create a mock ScanConfig
        mock_config = MagicMock()
        mock_config.failure_retry_cnt = 3
        mock_config.failure_multiplier_decrease = 0.20
        mock_config.failure_debounce_sec = 10.0
        mock_config.t_cnt.return_value = 8

        controller = MultiplierController()

        manager = create_retry_manager_from_config(
            scan_config=mock_config,
            thread_count_key='isalive',
            multiplier_controller=controller,
            thread_name_prefix="Test"
        )

        assert manager._base_workers == 8
        assert manager._retry_config.max_retries == 3
        mock_config.t_cnt.assert_called_with('isalive')
