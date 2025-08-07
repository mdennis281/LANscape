"""
Custom exceptions used by the lanscape application.

This module contains custom exception classes for handling various error cases
in the network scanning and device management operations.
"""


class SubnetTooLargeError(Exception):
    """Custom exception raised when the subnet size exceeds the allowed limit."""

    def __init__(self, subnet):
        self.subnet = subnet
        super().__init__(f"Subnet {subnet} exceeds the limit of IP addresses.")


class SubnetScanTerminationFailure(Exception):
    """Exception raised when subnet scanning threads cannot be terminated properly."""

    def __init__(self, running_threads):
        super().__init__(
            f'Unable to terminate active threads: {running_threads}')


class DeviceError(Exception):
    """Exception wrapper for device-related errors to provide context about failure source."""

    def __init__(self, e: Exception):
        self.base: Exception = e
        self.method = self._attempt_extract_method()

    def _attempt_extract_method(self):
        try:
            tb = self.base.__traceback__
            frame = tb.tb_frame
            return frame.f_code.co_name
        except Exception as e:
            print(e)
            return 'unknown'

    def __str__(self):
        return f'Error(source={self.method}, msg={self.base})'
