# /devmode — LANscape Live Dev Environment

Spin up the Python WebSocket backend and the React UI together, then attach the in-browser tools so you can see the UI in real time.

## Steps

### 1. Find the Python executable

The virtualenv lives in the **main project root**, not the worktree. Resolve it:

```bash
VENV_PYTHON=$(ls /c/Users/Michael/projects/py-net-scan/.env/Scripts/python.exe 2>/dev/null \
  || ls "$(git rev-parse --show-toplevel)/.env/Scripts/python.exe" 2>/dev/null \
  || echo "python3")
echo "Using: $VENV_PYTHON"
```

### 2. Start the dev servers

Run devmode.py in the background with `--no-browser` (Claude opens the browser instead).
`PYTHONIOENCODING=utf-8` is required to avoid emoji encoding errors on Windows.

```bash
PYTHONIOENCODING=utf-8 "$VENV_PYTHON" scripts/tasks/devmode.py --no-browser
```

Run this with `run_in_background: true`. Check the output after ~8 seconds to confirm both servers started and note the actual WS port (may auto-increment from 8766 if busy).

### 3. Wait for the UI to be ready

```bash
until curl -s http://localhost:3000 > /dev/null 2>&1; do sleep 1; done && echo "UI ready"
```

Timeout after 60 seconds. If the UI port is occupied, check devmode output for the actual port.

### 4. Read the actual WS port from devmode output

Look for a line like `Starting WebSocket server on port XXXX` in the background task output. Use that port in the URL (not always 8766).

### 5. Open the UI in Chrome

Use `mcp__Claude_in_Chrome__tabs_context_mcp` (with `createIfEmpty: true`) to get a tab ID, then navigate:

```
http://localhost:3000?ws-server=localhost:<actual-ws-port>
```

Take an initial screenshot with `mcp__Claude_in_Chrome__computer` (action: screenshot, save_to_disk: true) to confirm the UI loaded and the WebSocket is connected (green dot, bottom-right corner).

### 6. Ongoing inspection tools

Use these as needed during the debugging session:

| Goal | Tool |
|------|------|
| Take a screenshot | `mcp__Claude_in_Chrome__computer` (action: screenshot) |
| Read visible page text | `mcp__Claude_in_Chrome__get_page_text` |
| Click a button / element | `mcp__Claude_in_Chrome__find` then `mcp__Claude_in_Chrome__computer` (action: left_click) |
| Read browser console logs | `mcp__Claude_in_Chrome__read_console_messages` |
| Watch WebSocket traffic | `mcp__Claude_in_Chrome__read_network_requests` |
| Run JS in-page | `mcp__Claude_in_Chrome__javascript_tool` |
| Inspect DOM / CSS | `mcp__Claude_in_Chrome__read_page` |

### 7. Stopping

```bash
pkill -f "devmode.py" 2>/dev/null || taskkill /F /IM python.exe /T 2>/dev/null
```

Or tell the user to press Ctrl+C in their terminal if they launched it manually.

## Quick-reference ports

| Service | Default | Protocol |
|---------|---------|----------|
| Vite dev server | 3000 | HTTP |
| Python WebSocket | 8766 | WS (may auto-increment if busy) |

## Notes

- The Python backend runs `python -m lanscape --ws-server`. Changes to `lanscape/*.py` trigger hot-reload (watchdog).
- The React frontend runs Vite HMR — UI changes apply without refresh.
- Pass `--ws-port` or `--ui-port` to `devmode.py` to override defaults.
- The green dot in the bottom-right of the UI confirms WebSocket is connected.
- `PYTHONIOENCODING=utf-8` is always required when running from bash on Windows.
