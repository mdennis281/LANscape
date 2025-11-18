"""
Globals for tests in the LANscape project.
Provides shared configuration values used across multiple test files.
"""

from tests._helpers import right_size_subnet

TEST_SUBNET = f"1.1.1.1/28, {right_size_subnet()}"
MIN_EXPECTED_RUNTIME = 0.2
MIN_EXPECTED_ALIVE_DEVICES = 5
