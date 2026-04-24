---
description: Run pylint and fix issues until the score is 10/10. Use autopep8 for mass fixes when needed.
allowed-tools: Bash, Read, Edit, Glob, Grep
---

Fix the linting issues by running pylint (equivalent to the VS Code task "Run Linter (Pylint)"):

```bash
python -m pylint lanscape
```

If the score is less than 10/10, **that is not acceptable** — address the findings.

If there are a lot of issues, use autopep8 for mass corrections (equivalent to the VS Code task "Run Linter (Autopep8)"):

```bash
python -m autopep8 --in-place --recursive lanscape
```

Then re-run pylint.

Hard rules:

- Disabling imports outside of top-level is **never acceptable** unless there is a platform-specific constraint on the import.
- If a function has too many args, the fix is to introduce a Pydantic model — not to disable the rule.
- If you have to add any `# pylint: disable=...` rules, validate them with the user **before** adding.
