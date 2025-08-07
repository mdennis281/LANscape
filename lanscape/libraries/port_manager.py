"""
Port Manager module for managing port list configurations.

This module provides functionality to create, read, update, and delete port lists
that are stored as JSON files. Each port list contains port numbers and their
associated services. The module handles validation of port data and provides
methods for working with port list configurations.
"""

import json
from typing import List
from pathlib import Path
from .app_scope import ResourceManager

PORT_DIR = 'ports'


class PortManager:
    """
    Manager class for port list operations.

    Handles the creation, retrieval, updating, and deletion of port lists.
    Port lists are stored as JSON files with port numbers as keys and
    service names as values.
    """

    def __init__(self):
        """
        Initialize the PortManager.

        Creates the ports directory if it doesn't exist and initializes
        the ResourceManager for file operations.
        """
        Path(PORT_DIR).mkdir(parents=True, exist_ok=True)
        self.rm = ResourceManager(PORT_DIR)

    def get_port_lists(self) -> List[str]:
        """
        Get a list of all available port list names.

        Returns:
            List[str]: Names of all available port lists (without .json extension)
        """
        return [f.replace('.json', '') for f in self.rm.list() if f.endswith('.json')]

    def get_port_list(self, port_list: str) -> dict:
        """
        Retrieve a port list by name.

        Args:
            port_list (str): The name of the port list to retrieve

        Returns:
            dict: A dictionary of port numbers to service names

        Raises:
            ValueError: If the specified port list does not exist
        """
        if port_list not in self.get_port_lists():
            msg = f"Port list '{port_list}' does not exist. "
            msg += f"Available port lists: {self.get_port_lists()}"
            raise ValueError(msg)

        data = json.loads(self.rm.get(f'{port_list}.json'))

        return data if self.validate_port_data(data) else None

    def create_port_list(self, port_list: str, data: dict) -> bool:
        """
        Create a new port list.

        Args:
            port_list (str): Name for the new port list
            data (dict): Dictionary mapping port numbers to service names

        Returns:
            bool: True if creation was successful, False otherwise
        """
        if port_list in self.get_port_lists():
            return False
        if not self.validate_port_data(data):
            return False

        self.rm.create(f'{port_list}.json', json.dumps(data, indent=2))

        return True

    def update_port_list(self, port_list: str, data: dict) -> bool:
        """
        Update an existing port list.

        Args:
            port_list (str): Name of the port list to update
            data (dict): New dictionary mapping port numbers to service names

        Returns:
            bool: True if update was successful, False otherwise
        """
        if port_list not in self.get_port_lists():
            return False
        if not self.validate_port_data(data):
            return False

        self.rm.update(f'{port_list}.json', json.dumps(data, indent=2))

        return True

    def delete_port_list(self, port_list: str) -> bool:
        """
        Delete a port list.

        Args:
            port_list (str): Name of the port list to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        if port_list not in self.get_port_lists():
            return False

        self.rm.delete(f'{port_list}.json')

        return True

    def validate_port_data(self, port_data: dict) -> bool:
        """
        Validate port data structure and content.

        Ensures that:
        - Keys can be converted to integers
        - Values are strings
        - Port numbers are within valid range (0-65535)

        Args:
            port_data (dict): Dictionary mapping port numbers to service names

        Returns:
            bool: True if data is valid, False otherwise
        """
        try:
            for port, service in port_data.items():
                port = int(port)  # throws if not int
                if not isinstance(service, str):
                    return False

                if not 0 <= port <= 65535:
                    return False
            return True
        except BaseException:
            return False
