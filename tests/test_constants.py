"""
Global constants for tests in the LANscape project.
Provides shared configuration values used across multiple test files.
"""

# Test subnet for network scanning integration tests
# Using 1.1.1.1/28 (Cloudflare DNS range) for consistent, external testing
# This subnet contains 14 host addresses (1.1.1.1 - 1.1.1.14)
TEST_SUBNET = "1.1.1.1/28"

# Expected values for TEST_SUBNET
TEST_SUBNET_HOST_COUNT = 14  # Number of scannable host addresses
TEST_SUBNET_TOTAL_COUNT = 16  # Total addresses including network/broadcast

# Minimum expected runtime for integration tests (seconds)
# External IP scans should take at least some measurable time
MIN_EXPECTED_RUNTIME = 0.2

# For 1.1.1.1/28 range (Cloudflare DNS), using ICMP lookup finds all devices
# This provides a reliable test case with predictable results
MIN_EXPECTED_ALIVE_DEVICES = 10  # Expect at least 10 of the 14 to be alive
MAX_EXPECTED_ALIVE_DEVICES = TEST_SUBNET_HOST_COUNT  # All 14 typically respond to ICMP
