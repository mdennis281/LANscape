import json
import os
from typing import List
from pathlib import Path

PORT_DIR = './resources/ports/'

class PortManager:
    def __init__(self):
        Path(PORT_DIR).mkdir(parents=True, exist_ok=True)

        self.port_lists = self.get_port_lists()

    def get_port_lists(self) -> List[str]:
        return [f.replace('.json','') for f in os.listdir(PORT_DIR) if f.endswith('.json')]
    
    def get_port_list(self, port_list: str) -> dict:
        if port_list not in self.port_lists: raise ValueError(f"Port list '{port_list}' does not exist. Available port lists: {self.port_lists}")

        with open(f'{PORT_DIR}{port_list}.json', 'r') as f:
            data = json.load(f)

        return data if self.validate_port_data(data) else None
        
    def create_port_list(self, port_list: str, data: dict) -> bool:
        if port_list in self.port_lists: return False
        if not self.validate_port_data(data): return False

        with open(f'{PORT_DIR}{port_list}.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        self.port_lists = self.get_port_lists()
        return True
    
    def update_port_list(self, port_list: str, data: dict) -> bool:
        if port_list not in self.port_lists: return False
        if not self.validate_port_data(data): return False

        with open(f'{PORT_DIR}{port_list}.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        return True
    
    def delete_port_list(self, port_list: str) -> bool:
        if port_list not in self.port_lists: return False

        os.remove(f'{PORT_DIR}{port_list}.json')
        self.port_lists = self.get_port_lists()
        return True

    def validate_port_data(self, port_data: dict) -> bool:
        try:
            for port, service in port_data.items():
                port = int(port) # throws if not int
                if not isinstance(service, str): return False

                if not 0 <= port <= 65535: return False
            return True
        except:
            return False
        
