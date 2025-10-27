# Scripts Directory

This directory contains utility scripts for the py-net-scan project.

## Release Management Scripts

### `tag_release.ps1`
PowerShell script for tagging releases manually. 

**Usage:**
```powershell
.\scripts\tag_release.ps1 -Version "1.2.3"
```

### `generate_release_notes.py`
Python script that generates AI-powered release notes using OpenAI's API.

**Requirements:**
- `openai` Python package
- `OPENAI_API_KEY` environment variable set

**Usage:**
```bash
# For first release (includes all commits)
python scripts/generate_release_notes.py "1.0.0"

# For subsequent releases (commits since previous tag)
python scripts/generate_release_notes.py "1.2.0" "releases/1.1.0"
```

**Environment Setup:**
```bash
pip install openai
export OPENAI_API_KEY="your-api-key-here"
```

## Automated Release Workflow

The project uses GitHub Actions to automatically:

1. **Tag releases** when commits to `main` start with semantic version (e.g., "1.2.3 Add new feature")
2. **Create GitHub releases** with AI-generated descriptions
3. **Publish to PyPI** automatically

### Required Secrets

Set these in your GitHub repository settings:

- `OPENAI_API_KEY` - Your OpenAI API key for generating release descriptions
- `PYPI_USERNAME` - Your PyPI username
- `PYPI_PASSWORD` - Your PyPI API token

### Workflow Files

- `.github/workflows/tag-on-main-push.yml` - Main workflow that tags releases and orchestrates the release process
- `.github/workflows/create-release.yml` - Reusable workflow that creates GitHub releases with AI-generated descriptions  
- `.github/workflows/pypi-publish.yml` - Reusable workflow that publishes packages to PyPI