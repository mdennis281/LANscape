import json
from typing import List
from pathlib import Path
from .app_scope import ResourceManager

PORT_DIR = 'ports'


class PortManager:
    def __init__(self):
        Path(PORT_DIR).mkdir(parents=True, exist_ok=True)
        self.rm = ResourceManager(PORT_DIR)

    def get_port_lists(self) -> List[str]:
        return [f.replace('.json', '') for f in self.rm.list() if f.endswith('.json')]

    def get_port_list(self, port_list: str) -> dict:

        if port_list not in self.get_port_lists():
            msg = f"Port list '{port_list}' does not exist. "
            msg += f"Available port lists: {self.get_port_lists()}"
            raise ValueError(msg)

        data = json.loads(self.rm.get(f'{port_list}.json'))

        return data if self.validate_port_data(data) else None

    def create_port_list(self, port_list: str, data: dict) -> bool:
        if port_list in self.get_port_lists():
            return False
        if not self.validate_port_data(data):
            return False

        self.rm.create(f'{port_list}.json', json.dumps(data, indent=2))

        return True

    def update_port_list(self, port_list: str, data: dict) -> bool:
        if port_list not in self.get_port_lists():
            return False
        if not self.validate_port_data(data):
            return False

        self.rm.update(f'{port_list}.json', json.dumps(data, indent=2))

        return True

    def delete_port_list(self, port_list: str) -> bool:
        if port_list not in self.get_port_lists():
            return False

        self.rm.delete(f'{port_list}.json')

        return True

    def validate_port_data(self, port_data: dict) -> bool:
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
