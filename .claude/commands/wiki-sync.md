---
description: Sync ./docs/wiki/ when schemas/models change or features are added/removed.
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

There is a wiki under `./docs/wiki/` that tracks usage docs for consuming LANScape as a library or as a WebSocket server. If the current changes affect schemas/models or add/remove features, the wiki **must** be updated.

Before making changes:

1. Read enough of `./docs/wiki/` to understand how the wiki is structured and formatted.
2. Read the GitHub workflow at `.github/workflows/chore-wiki-sync.yml` so you understand the automation that consumes these files.

Include **clear examples** and relevant code snippets. This is critical for developers who want to use the library or WebSocket server in their own projects, and it also keeps a running record of changes over time.

Once finished, re-read the files you touched and verify them for relevancy and accuracy. If anything feels potentially problematic and you aren't sure, ask the user before finalizing.
