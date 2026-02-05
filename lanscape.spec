# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for LANscape backend.

Builds a single executable that runs the LANscape WebSocket server.
Usage: pyinstaller lanscape.spec
"""

import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all lanscape submodules
hiddenimports = collect_submodules('lanscape')

# Add additional hidden imports that PyInstaller might miss
hiddenimports += [
    'websockets',
    'websockets.server',
    'websockets.legacy',
    'websockets.legacy.server',
    'pydantic',
    'pydantic.deprecated',
    'pydantic.deprecated.decorator',
    'icmplib',
    'scapy',
    'scapy.all',
    'scapy.layers',
    'scapy.layers.l2',
    'scapy.layers.inet',
    'flask',
    'psutil',
    'tabulate',
]

# Collect data files (port lists, resources, etc.)
datas = [
    ('lanscape/resources', 'lanscape/resources'),  # Include resource files (ports, services, mac addresses)
]

a = Analysis(
    ['lanscape/__main__.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # Use onedir mode for fast startup
    name='lanscape-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=True,  # Console app for WebSocket server
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path if desired
)

# Collect all files into a directory
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='lanscape-backend',
)
