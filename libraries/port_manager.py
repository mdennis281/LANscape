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
        return [f.strip('.json') for f in os.listdir(PORT_DIR) if f.endswith('.json')]
    
    def get_port_list(self, port_list: str) -> dict:
        if port_list not in self.port_lists: return None

        with open(f'{PORT_DIR}{port_list}.json', 'r') as f:
            return json.load(f)
        
    def create_port_list(self, port_list: str, data: dict) -> bool:
        if port_list in self.port_lists: return False

        with open(f'{PORT_DIR}{port_list}.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        self.port_lists = self.get_port_lists()
        return True
    
    def delete_port_list(self, port_list: str) -> bool:
        if port_list not in self.port_lists: return False

        os.remove(f'{PORT_DIR}{port_list}.json')
        self.port_lists = self.get_port_lists()
        return True

