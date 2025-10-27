"""Tests for helper decorators used throughout the project."""

import logging
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

from lanscape.core.decorators import run_once, job_tracker, JobStats


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


class TestJobStats(unittest.TestCase):
    """Test the JobStats singleton implementation."""

    def setUp(self):
        """Reset JobStats singleton for each test."""
        JobStats.reset_for_testing()

    def tearDown(self):
        """Clean up after each test."""
        JobStats.reset_for_testing()

    def test_singleton_behavior(self):
        """JobStats should behave as a singleton."""
        stats1 = JobStats()
        stats2 = JobStats()

        assert stats1 is stats2
        assert id(stats1) == id(stats2)

    def test_thread_safe_singleton_creation(self):
        """Multiple threads creating JobStats should get the same instance."""
        instances = []
        barrier = threading.Barrier(5)

        def create_instance():
            barrier.wait()  # Synchronize thread start
            instance = JobStats()
            instances.append(instance)

        # Create multiple threads that create JobStats instances simultaneously
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=create_instance)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All instances should be the same
        assert len(instances) == 5
        assert all(inst is instances[0] for inst in instances)

    def test_start_and_finish_job(self):
        """Test basic job tracking functionality."""
        stats = JobStats()

        # Start a job
        stats.start_job("test_function")
        assert stats.running["test_function"] == 1
        assert stats.finished["test_function"] == 0

        # Finish the job
        stats.finish_job("test_function", 1.5)
        assert stats.running.get("test_function", 0) == 0  # Should be cleaned up
        assert stats.finished["test_function"] == 1
        assert stats.timing["test_function"] == 1.5

    def test_multiple_jobs_same_function(self):
        """Test tracking multiple executions of the same function."""
        stats = JobStats()

        # Start and finish multiple jobs
        stats.start_job("test_func")
        stats.finish_job("test_func", 1.0)

        stats.start_job("test_func")
        stats.finish_job("test_func", 3.0)

        # Should have correct counts and average timing
        assert stats.finished["test_func"] == 2
        assert stats.timing["test_func"] == 2.0  # Average of 1.0 and 3.0

    def test_concurrent_job_tracking(self):
        """Test thread-safe job tracking under concurrent load."""
        stats = JobStats()
        results = []

        def worker(job_id):
            func_name = f"test_job_{job_id % 3}"  # 3 different function names
            stats.start_job(func_name)
            time.sleep(0.01)  # Simulate work
            stats.finish_job(func_name, 0.01)
            return func_name

        # Run multiple concurrent workers
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(50)]
            for future in as_completed(futures):
                results.append(future.result())

        # Verify no jobs are left running
        assert len(stats.running) == 0

        # Verify correct totals
        total_finished = sum(stats.finished.values())
        assert total_finished == 50

        # Each function should have been called multiple times
        for i in range(3):
            func_name = f"test_job_{i}"
            assert stats.finished[func_name] > 0
            assert stats.timing[func_name] > 0

    def test_clear_stats(self):
        """Test clearing all statistics."""
        stats = JobStats()

        # Add some data
        stats.start_job("test1")
        stats.finish_job("test1", 1.0)
        stats.start_job("test2")

        # Verify data exists
        assert len(stats.running) > 0 or len(stats.finished) > 0

        # Clear and verify
        stats.clear_stats()
        assert len(stats.running) == 0
        assert len(stats.finished) == 0
        assert len(stats.timing) == 0

    def test_get_stats_copy(self):
        """Test getting a thread-safe copy of statistics."""
        stats = JobStats()

        stats.start_job("test")
        stats.finish_job("test", 2.5)

        copy = stats.get_stats_copy()

        # Should be a copy, not the same objects
        assert copy['running'] is not stats.running
        assert copy['finished'] is not stats.finished
        assert copy['timing'] is not stats.timing

        # But should have the same data
        assert copy['finished']['test'] == 1
        assert copy['timing']['test'] == 2.5


class TestJobTracker(unittest.TestCase):
    """Test the job_tracker decorator."""

    def setUp(self):
        """Reset JobStats singleton for each test."""
        JobStats.reset_for_testing()

    def tearDown(self):
        """Clean up after each test."""
        JobStats.reset_for_testing()

    def test_basic_function_tracking(self):
        """Test basic function tracking with decorator."""

        @job_tracker
        def test_function():
            time.sleep(0.01)
            return "result"

        result = test_function()

        assert result == "result"

        stats = JobStats()
        assert stats.finished["test_function"] == 1
        assert stats.timing["test_function"] > 0
        assert len(stats.running) == 0  # Should be cleaned up

    def test_method_tracking_with_class_name(self):
        """Test that class methods are tracked with class.method naming."""

        class TestClass:
            """Test class for method tracking."""

            @job_tracker
            def test_method(self):
                """Test method that returns a string."""
                time.sleep(0.01)
                return "method_result"

        obj = TestClass()
        result = obj.test_method()

        assert result == "method_result"

        stats = JobStats()
        assert stats.finished["TestClass.test_method"] == 1
        assert stats.timing["TestClass.test_method"] > 0

    def test_exception_handling(self):
        """Test that statistics are updated even when function raises exception."""

        @job_tracker
        def failing_function():
            time.sleep(0.01)
            raise ValueError("Test exception")

        with self.assertRaises(ValueError):
            failing_function()

        stats = JobStats()
        assert stats.finished["failing_function"] == 1
        assert stats.timing["failing_function"] > 0
        assert len(stats.running) == 0  # Should be cleaned up

    def test_concurrent_decorated_functions(self):
        """Test decorator behavior under concurrent execution."""

        @job_tracker
        def concurrent_task(task_id):
            time.sleep(0.01)
            return task_id

        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(concurrent_task, i) for i in range(20)]
            for future in as_completed(futures):
                results.append(future.result())

        assert len(results) == 20

        stats = JobStats()
        assert stats.finished["concurrent_task"] == 20
        assert stats.timing["concurrent_task"] > 0
        assert len(stats.running) == 0  # All should be cleaned up

    def test_multiple_different_functions(self):
        """Test tracking multiple different decorated functions."""

        @job_tracker
        def function_a():
            time.sleep(0.01)
            return "a"

        @job_tracker
        def function_b():
            time.sleep(0.02)
            return "b"

        function_a()
        function_b()
        function_a()

        stats = JobStats()
        assert stats.finished["function_a"] == 2
        assert stats.finished["function_b"] == 1
        assert stats.timing["function_a"] > 0
        assert stats.timing["function_b"] > stats.timing["function_a"]  # b sleeps longer
