

class SubnetTooLargeError(Exception):
    """Custom exception raised when the subnet size exceeds the allowed limit."""
    def __init__(self, subnet):
        self.subnet = subnet
        super().__init__(f"Subnet {subnet} exceeds the limit of IP addresses.")
