
"""
Resource and environment management utilities for Lanscape.
"""

from pathlib import Path
from importlib.metadata import version, PackageNotFoundError
import json


class ResourceManager:
    """
    A class to manage assets in the resources folder.
    Works locally and if installed based on relative path from this file.
    """

    def __init__(self, asset_folder: str):
        """Initialize the resource manager with a specific asset folder."""
        self.asset_dir = self._get_resource_path() / asset_folder

    def list(self):
        """List all asset names in the asset directory."""
        return [p.name for p in self.asset_dir.iterdir()]

    def get(self, asset_name: str):
        """Get the content of an asset as a string."""
        with open(self.asset_dir / asset_name, 'r', encoding='utf-8') as f:
            return f.read()

    def get_json(self, asset_name: str):
        """Get the content of an asset as a JSON object."""
        return json.loads(self.get(asset_name))

    def get_jsonc(self, asset_name: str):
        """AI Slop to get JSONC (JSON with comments) content of an asset as a JSON object."""
        content = self.get(asset_name)

        def strip_jsonc_lines(text):
            result = []
            in_string = False
            escape = False
            for line in text.splitlines():
                new_line = []
                i = 0
                while i < len(line):
                    char = line[i]
                    if char == '"' and not escape:
                        in_string = not in_string
                    if not in_string and line[i:i + 2] == "//":
                        break  # Ignore rest of line (comment)
                    new_line.append(char)
                    escape = (char == '\\' and not escape)
                    i += 1
                result.append(''.join(new_line))
            return '\n'.join(result)
        cleaned_content = strip_jsonc_lines(content)
        return json.loads(cleaned_content)

    def update(self, asset_name: str, content: str):
        """Update the content of an existing asset."""
        with open(self.asset_dir / asset_name, 'w', encoding='utf-8') as f:
            f.write(content)

    def create(self, asset_name: str, content: str):
        """Create a new asset with the given content."""
        if (self.asset_dir / asset_name).exists():
            raise FileExistsError(f"File {asset_name} already exists")
        with open(self.asset_dir / asset_name, 'w', encoding='utf-8') as f:
            f.write(content)

    def delete(self, asset_name: str):
        """Delete an asset from the asset directory."""
        (self.asset_dir / asset_name).unlink()

    def _get_resource_path(self) -> Path:
        """Get the path to the resources directory."""
        base_dir = Path(__file__).parent.parent
        resource_dir = base_dir / "resources"
        return resource_dir


def is_local_run() -> bool:
    """
    Determine if the code is running locally or as an installed package.

    Returns ``True`` only when the package has **not** been installed at
    all (i.e. running directly from source without ``pip install``).
    Editable installs (``pip install -e .``) are treated as *installed*
    because they register proper package metadata with a real version.
    """
    try:
        version('lanscape')
        return False  # metadata exists → installed (regular or editable)
    except PackageNotFoundError:
        return True   # no metadata → truly running from raw source
