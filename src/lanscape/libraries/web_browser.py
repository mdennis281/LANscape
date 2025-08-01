#!/usr/bin/env python3
"""
Get the executable path of the system’s default web browser.

Supports:
  - Windows (reads from the registry)
  - Linux   (uses xdg-mime / xdg-settings + .desktop file parsing)
"""

import sys
import os
import subprocess
import webbrowser
import logging
import re
import time
from typing import Optional
from ..ui.app import app

log = logging.getLogger('WebBrowser')


def open_webapp(url: str) -> bool:
    """
    will try to open the web page as an app
    on failure, will open as a tab in default browser

    returns: 
    """
    start = time.time()
    try:
        exe = get_default_browser_executable()
        if not exe:
            raise RuntimeError('Unable to find browser binary')
        log.debug(f'Opening {url} with {exe}')

        cmd = f'"{exe}" --app="{url}"'
        subprocess.run(cmd, check=True, shell=True)

        if time.time() - start < 2:
            log.debug(f'Unable to hook into closure of UI, listening for flask shutdown')
            return False
        return True
        
    except Exception as e:
        log.warning('Failed to open webpage as app, falling back to browser tab')
        log.debug(f'As app error: {e}')
        try:
            success = webbrowser.open(url)
            log.debug(f'Opened {url} in browser tab: {success}')
            if not success:
                raise RuntimeError('Unknown error while opening browser tab')
        except Exception as e:
            log.warning(f'Exhausted all options to open browser, you need to open manually')
            log.debug(f'As tab error: {e}')
            log.info(f'LANScape UI is running on {url}')
    return False
    

def get_default_browser_executable() -> Optional[str]:
    if sys.platform.startswith("win"):
        try:
            import winreg
            # On Windows the HKEY_CLASSES_ROOT\http\shell\open\command key
            # holds the command for opening HTTP URLs.
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"http\shell\open\command") as key:
                cmd, _ = winreg.QueryValueEx(key, None)
        except Exception:
            return None

        # cmd usually looks like: '"C:\\Program Files\\Foo\\foo.exe" %1'
        m = re.match(r'\"?(.+?\.exe)\"?', cmd)
        return m.group(1) if m else None

    elif sys.platform.startswith("linux"):
        # First, find the .desktop file name
        desktop_file = None
        try:
            # Try xdg-mime
            p = subprocess.run(
                ["xdg-mime", "query", "default", "x-scheme-handler/http"],
                capture_output=True, text=True,
                check=True
            )
            desktop_file = p.stdout.strip()
        except subprocess.CalledProcessError:
            pass

        if not desktop_file:
            # Fallback to xdg-settings
            try:
                p = subprocess.run(
                    ["xdg-settings", "get", "default-web-browser"],
                    capture_output=True, text=True,
                    check=True
                )
                desktop_file = p.stdout.strip()
            except subprocess.CalledProcessError:
                pass

        # Final fallback: BROWSER environment variable
        if not desktop_file:
            return os.environ.get("BROWSER")

        # Look for that .desktop file in standard locations
        search_paths = [
            os.path.expanduser("~/.local/share/applications"),
            "/usr/local/share/applications",
            "/usr/share/applications",
        ]
        for path in search_paths:
            full_path = os.path.join(path, desktop_file)
            if os.path.isfile(full_path):
                with open(full_path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("Exec="):
                            exec_cmd = line[len("Exec="):].strip()
                            # strip arguments like “%u”, “--flag”, etc.
                            exec_cmd = exec_cmd.split()[0]
                            exec_cmd = exec_cmd.split("%")[0]
            return exec_cmd
        return None

    elif sys.platform.startswith("darwin"):
        # macOS: try to find Chrome first for app mode support, fallback to default
        try:
            p = subprocess.run(
                ["mdfind", "kMDItemCFBundleIdentifier == 'com.google.Chrome'"],
                capture_output=True, text=True, check=True
            )
            chrome_paths = p.stdout.strip().split('\n')
            if chrome_paths and chrome_paths[0]:
                return f"{chrome_paths[0]}/Contents/MacOS/Google Chrome"
        except subprocess.CalledProcessError:
            pass
        
        # Fallback to system default
        return "/usr/bin/open"

    else:
        raise NotImplementedError(f"Unsupported platform: {sys.platform!r}")
