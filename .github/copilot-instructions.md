LANScape - A python based local network scanner.

Things to remember, every change needs:
- Passing tests
  - `python -m unittest` for larger stuff
  - `pytest` on individual test files for smaller stuff
- Approval for any changed requirements in requirements.txt
- Any changed requirements must be also added to pyproject.toml
- Passing pylint checks (inline exceptions allowed, not for the project as a whole)
- Syntax appropriate for python 3.10+
- Type hints for all functions and methods
- New features classes and features need to be added to `./lanscape/__init__.py` for proper module exports


Preferences:
- Pydantic models for structured data
- Use requests for HTTP calls
- Threadpooling over async where applicable