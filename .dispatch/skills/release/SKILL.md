---
name: release
description: Cut a LANscape release or pre-release — choose the version, pick the lanscape-ui branch, push the tag, and know which artifacts each tag prefix produces. Use when asked to release, ship a version, cut an RC/beta/alpha, or publish to PyPI.
---

# Releasing LANscape

The version exists **only as a git tag**. `pyproject.toml` stays at `0.0.0`;
`release-pypi-publish.yml` seds the real version in at build time.

## Two ways a release happens

**1. Merging a PR to `main` (the normal path).** The PR title *is* the version —
`X.Y.Z - Description`, higher than the newest `releases/*` tag. On merge,
`release-trigger-main-push.yml` creates and pushes `releases/X.Y.Z`. Nothing
else to do. Every human merge ships; there is no non-releasing merge.

**2. Tagging directly (for pre-releases, or a non-`main` UI branch).** Use the
script — it prints the current release / alpha / beta / rc tags first so you can
pick the next version without guessing:

```
scripts/tasks/tag_release.ps1                      # Windows (VS Code: "Tag and Push Release")
scripts/tasks/tag_release.sh                       # macOS/Linux
scripts/tasks/tag_release.sh 4.2.0rc1 --ui-branch main
```

It prompts for the version and the UI branch if you do not pass them.

## What the version string decides

The script picks the tag prefix from the version, and
`release-trigger-tag-push.yml` picks the artifacts from the prefix:

| Version        | Tag                    | GitHub release | PyPI publish |
| -------------- | ---------------------- | -------------- | ------------ |
| `4.2.0`        | `releases/4.2.0`       | yes            | yes          |
| `4.2.0rc1`     | `pre-releases/4.2.0rc1`| yes (pre)      | yes          |
| `4.2.0b1`      | `pre-releases/4.2.0b1` | no             | yes          |
| `4.2.0a1`      | `pre-releases/4.2.0a1` | no             | yes          |

Anything else produces no release at all.

## The UI build gates the publish

Every release dispatches `webapp-build.yml` in `mdennis281/lanscape-ui`, waits
up to 20 minutes, and pulls back the `webapp-dist` artifact — that is what fills
the empty `lanscape/ui/react_build/`. The `publish` job requires
`trigger-ui-build` to have succeeded, so **a failing UI build blocks the PyPI
release.** Needs the `UI_BUILD_PAT` secret.

If you pass `--ui-branch` anything other than `main`, the script does *not* push
a tag; it runs `gh workflow run release-trigger-tag-push.yml` so the workflow
can create the tag with that branch wired in. That path needs the `gh` CLI
installed and authenticated.

## Housekeeping

`chore-cleanup-prereleases.yml` prunes `pre-releases/*` tags older than 90 days,
monthly on the 1st. Run it by hand via workflow_dispatch with a different
`max_age_days` if you need a deeper sweep.
