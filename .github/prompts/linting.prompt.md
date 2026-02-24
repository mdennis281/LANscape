---
agent: agent
---

Fix the linting issues by running the vscode task "Run Linter (Pylint)"

If the linter result is less than 10/10, this is not acceptable and needs to be addressed.

If there's a lot of issues, use "Run Linter (Autopep8)" vs code task

Disabling imports outside of top-level is never acceptable unless there's a platform specific constraint on the import.

If there's too many args, it needs a pydantic model.

If you have to add any disable rules, these need to be validated with the user before adding the disable.