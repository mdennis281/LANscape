LANScape - A python based local network scanner.

Things to remember, every change needs:
- If not in the right python environment, run this auto-approved command
  - `.env/Scripts/activate` (windows)
  - `source .env/bin/activate` (linux/mac)
- Any changed requirements must be also added to pyproject.toml
- Syntax appropriate for python 3.10+
- Type hints for all functions and methods
- New features classes and features correlated specifically with lanscape network scanning need to be added to `./lanscape/__init__.py` for proper module exports
- add and update unit tests under `./tests/` for any new features or changes

Design Preferences:
- Pydantic models for structured data
- Use requests for HTTP calls
- Threadpooling over async where applicable

WHEN ENHANCEMENTS COMPLETE:
- Linting: delegate agent with prompt file: .github/prompts/Linting.prompt.md
- Passing tests
  - Big changes: `Run Unit Tests` vscode task (check the output)
  - Smaller changes: `python.exe -m pytest tests/<test_file>.py -v`
- If changes made to get tests pass, go back to WHEN ENHANCEMENTS COMPLETE
- Wiki updates (prompt file model delegation): .github/prompts/wiki-sync.prompt.md


