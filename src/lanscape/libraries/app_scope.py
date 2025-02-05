from pathlib import Path
import json
import sys
import re

class ResourceManager:
    """
    A class to manage assets in the resources folder.
    Works locally and if installed based on relative path from this file
    """
    def __init__(self, asset_folder: str):
        self.asset_dir = self._get_resource_path() / asset_folder
        
    def list(self):
        return [p.name for p in self.asset_dir.iterdir()]
    
    def get(self, asset_name: str):
        with open(self.asset_dir / asset_name, 'r') as f:
            return f.read()
        
    def get_json(self, asset_name: str):
        return json.loads(self.get(asset_name))
    
    def get_jsonc(self, asset_name: str):
        " Get JSON content with comments removed "
        content = self.get(asset_name)
        cleaned_content = re.sub(r'//.*', '', content)
        return json.loads(cleaned_content)

        
    def update(self, asset_name: str, content: str):
        with open(self.asset_dir / asset_name, 'w') as f:
            f.write(content)

    def create(self, asset_name: str, content: str):
        if (self.asset_dir / asset_name).exists():
            raise FileExistsError(f"File {asset_name} already exists")
        with open(self.asset_dir / asset_name, 'w') as f:
            f.write(content)
    
    def delete(self, asset_name: str):
        (self.asset_dir / asset_name).unlink()
        
    def _get_resource_path(self) -> Path:
        base_dir = Path(__file__).parent.parent
        resource_dir = base_dir / "resources"
        return resource_dir




def is_local_run(module_name: str = 'lanscape') -> bool:
    """
    Determine if the code is running locally or as an installed PyPI package.
    """
    module_path = Path(__file__).parent

    # Check if the path is in site-packages/dist-packages
    if module_path and any(part in module_path.parts for part in ['site-packages', 'dist-packages']):
        return False  # Installed package

    # Check for a .git directory in the path or its parents
    if module_path and any((parent / ".git").exists() for parent in module_path.parents):
        return True  # Local development

    # Check sys.path for non-standard local paths
    if any(not str(Path(p)).startswith(('/usr', '/lib', '/site-packages')) for p in sys.path):
        return True  # Local run

    return False  # Default to installed package
