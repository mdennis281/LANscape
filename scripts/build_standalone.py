#!/usr/bin/env python3
"""
Build script for LANscape standalone executable.

Creates a single executable using PyInstaller that can be bundled
with the Electron frontend.

Usage:
    python scripts/build_standalone.py [--output-dir PATH]
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def get_executable_name() -> str:
    """Get the platform-specific executable name."""
    system = platform.system().lower()
    if system == 'windows':
        return 'lanscape-backend.exe'
    return 'lanscape-backend'


def get_platform_suffix() -> str:
    """Get platform suffix for the output file."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == 'windows':
        return 'win-x64'
    elif system == 'darwin':
        if machine in ('arm64', 'aarch64'):
            return 'macos-arm64'
        return 'macos-x64'
    elif system == 'linux':
        if machine in ('arm64', 'aarch64'):
            return 'linux-arm64'
        return 'linux-x64'
    return f'{system}-{machine}'


def build_executable(output_dir: Path) -> Path:
    """
    Build the standalone executable using PyInstaller.

    Args:
        output_dir: Directory to place the final executable

    Returns:
        Path to the built executable
    """
    project_root = Path(__file__).parent.parent
    spec_file = project_root / 'lanscape.spec'

    if not spec_file.exists():
        raise FileNotFoundError(f"Spec file not found: {spec_file}")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Clean previous builds
    dist_dir = project_root / 'dist'
    build_dir = project_root / 'build'

    print(f"Building LANscape standalone executable...")
    print(f"  Platform: {get_platform_suffix()}")
    print(f"  Output: {output_dir}")

    # Run PyInstaller
    result = subprocess.run(
        [
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            '--noconfirm',
            str(spec_file)
        ],
        cwd=project_root,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("PyInstaller failed:")
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError("PyInstaller build failed")

    # Find the built executable
    exe_name = get_executable_name()
    built_exe = dist_dir / exe_name

    if not built_exe.exists():
        raise FileNotFoundError(f"Built executable not found: {built_exe}")

    # Copy to output directory with platform suffix
    platform_suffix = get_platform_suffix()
    if platform.system().lower() == 'windows':
        final_name = f'lanscape-backend-{platform_suffix}.exe'
    else:
        final_name = f'lanscape-backend-{platform_suffix}'

    final_path = output_dir / final_name
    shutil.copy2(built_exe, final_path)

    # Also copy without suffix for local testing
    local_copy = output_dir / exe_name
    shutil.copy2(built_exe, local_copy)

    # Get file size
    size_mb = final_path.stat().st_size / (1024 * 1024)
    print(f"  Built: {final_name} ({size_mb:.1f} MB)")

    # Clean up build artifacts (optional)
    # shutil.rmtree(build_dir, ignore_errors=True)

    return final_path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Build LANscape standalone executable'
    )
    parser.add_argument(
        '--output-dir', '-o',
        type=Path,
        default=Path(__file__).parent.parent / 'dist' / 'standalone',
        help='Output directory for the executable'
    )
    args = parser.parse_args()

    try:
        exe_path = build_executable(args.output_dir)
        print(f"\nBuild successful: {exe_path}")
        return 0
    except Exception as e:
        print(f"\nBuild failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
