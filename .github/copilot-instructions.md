LANScape - A python based local network scanner.

Things to remember, every change needs:
- If not in the right python environment, run this auto-approved command
  - `.env/Scripts/activate` (windows)
  - `source .env/bin/activate` (linux/mac)
- Passing tests
  - Big changes: `python -m unittest"`
  - Smaller changes: `python.exe -m pytest tests/<test_file>.py -v`
- Any changed requirements must be also added to pyproject.toml
- There is an auto-pep8 
- Passing pylint checks (inline exceptions allowed, not for the project as a whole)
  - Run `python -m pylint --score=yes scripts/ tests/ lanscape/`
- Syntax appropriate for python 3.10+
- Type hints for all functions and methods
- New features classes and features need to be added to `./lanscape/__init__.py` for proper module exports


Preferences:
- Pydantic models for structured data
- Use requests for HTTP calls
- Threadpooling over async where applicable