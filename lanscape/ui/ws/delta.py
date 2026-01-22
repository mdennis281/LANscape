"""
Delta tracking for efficient scan result updates.

Uses content hashing to detect changes and only send updated data
to clients, reducing bandwidth and improving performance.
"""

import json
import hashlib
from typing import Any, Optional

from pydantic import BaseModel


class DeltaState(BaseModel):
    """
    Represents the state of a tracked item.

    Attributes:
        hash: Content hash of the serialized data
        data: The actual data being tracked
    """
    hash: str
    data: Any


class DeltaTracker:
    """
    Tracks changes to scan results and provides delta updates.

    Uses MD5 hashing to detect changes in device data and scan state.
    Clients receive only the changed portions of scan results.
    """

    def __init__(self):
        """Initialize the delta tracker with empty state."""
        self._states: dict[str, DeltaState] = {}

    @staticmethod
    def compute_hash(data: Any) -> str:
        """
        Compute MD5 hash of serialized data.

        Args:
            data: Any JSON-serializable data

        Returns:
            Hex string of the MD5 hash
        """
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(serialized.encode()).hexdigest()

    def update(self, key: str, data: Any) -> Optional[Any]:
        """
        Update tracked state and return data if changed.

        Args:
            key: Unique identifier for the tracked item
            data: Current data for the item

        Returns:
            The data if it has changed, None otherwise
        """
        new_hash = self.compute_hash(data)
        current_state = self._states.get(key)

        if current_state is None or current_state.hash != new_hash:
            self._states[key] = DeltaState(hash=new_hash, data=data)
            return data
        return None

    def get_changes(self, items: dict[str, Any]) -> dict[str, Any]:
        """
        Get only changed items from a dictionary.

        Args:
            items: Dictionary of key -> data to check for changes

        Returns:
            Dictionary containing only the changed items
        """
        changes = {}
        for key, data in items.items():
            result = self.update(key, data)
            if result is not None:
                changes[key] = result
        return changes

    def reset(self, key: Optional[str] = None) -> None:
        """
        Reset tracked state.

        Args:
            key: Specific key to reset, or None to reset all
        """
        if key is not None:
            self._states.pop(key, None)
        else:
            self._states.clear()

    def has_key(self, key: str) -> bool:
        """
        Check if a key is being tracked.

        Args:
            key: The key to check

        Returns:
            True if the key is tracked, False otherwise
        """
        return key in self._states

    def get_hash(self, key: str) -> Optional[str]:
        """
        Get the current hash for a tracked key.

        Args:
            key: The key to get the hash for

        Returns:
            The current hash, or None if not tracked
        """
        state = self._states.get(key)
        return state.hash if state else None


class ScanDeltaTracker(DeltaTracker):
    """
    Specialized delta tracker for scan results.

    Tracks individual devices and overall scan metadata,
    providing efficient delta updates for real-time scan monitoring.
    """

    def get_scan_delta(self, scan_results: dict) -> dict:
        """
        Get delta update for scan results.

        Args:
            scan_results: Full scan results dictionary

        Returns:
            Dictionary containing only changed fields:
            - 'devices': List of changed device data
            - 'metadata': Changed scan metadata (if any)
            - 'has_changes': Boolean indicating if there are any changes
        """
        delta = {
            'devices': [],
            'metadata': None,
            'has_changes': False
        }

        # Track metadata changes (everything except devices)
        metadata = {k: v for k, v in scan_results.items() if k != 'devices'}
        metadata_change = self.update('_metadata', metadata)
        if metadata_change is not None:
            delta['metadata'] = metadata_change
            delta['has_changes'] = True

        # Track individual device changes
        devices = scan_results.get('devices', [])
        for device in devices:
            device_ip = device.get('ip', str(id(device)))
            device_change = self.update(f'device_{device_ip}', device)
            if device_change is not None:
                delta['devices'].append(device_change)
                delta['has_changes'] = True

        return delta
