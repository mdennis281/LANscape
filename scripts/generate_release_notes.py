#!/usr/bin/env python3
"""
Generate release notes using OpenAI API based on git commit history.
"""

import os
import sys
import subprocess
from typing import Optional
import openai

# GitHub release body limit with safety margin
MAX_RELEASE_BODY_LENGTH = 120000  # 120KB (5KB safety margin)
MAX_GIT_LOG_LENGTH = 80000  # Limit input to leave room for AI output
MAX_FILE_DIFF_SIZE = 5000  # Limit per-file diff size


def _truncate_text(
        text: str,
        max_length: int,
        suffix: str = "\n\n... (truncated for brevity)") -> str:
    """Truncate text to max_length, preserving complete lines when possible."""
    if len(text) <= max_length:
        return text

    # Try to truncate at a line boundary
    truncate_point = max_length - len(suffix)
    last_newline = text.rfind('\n', 0, truncate_point)

    if last_newline > max_length * 0.8:  # If we can preserve at least 80% of content
        return text[:last_newline] + suffix
    return text[:truncate_point] + suffix


def _get_commit_log(from_tag: Optional[str], to_tag: str) -> str:
    """Get git commit log with statistics."""
    if from_tag:
        log_cmd = [
            "git", "log", "--stat",
            "--pretty=format:### %s (%an)%n",
            f"{from_tag}..{to_tag}"
        ]
    else:
        log_cmd = [
            "git", "log", "--stat",
            "--pretty=format:### %s (%an)%n",
            to_tag
        ]

    result = subprocess.run(log_cmd, capture_output=True, text=True,
                            check=True, encoding='utf-8', errors='replace')
    return result.stdout.strip() if result.stdout else ""


def _get_file_diffs(from_tag: str, to_tag: str) -> str:
    """Get per-file diffs for changed files with size limits."""
    output = "\n\n## Code Changes by File\n"

    # Get list of changed files
    cmd = ["git", "diff", "--name-only", f"{from_tag}..{to_tag}"]
    result = subprocess.run(cmd, capture_output=True, text=True,
                            check=True, encoding='utf-8', errors='replace')
    if not result.stdout:
        return output

    changed_files = [f.strip()
                     for f in result.stdout.strip().split('\n') if f.strip()]
    original_count = len(changed_files)
    # Limit number of files to prevent excessive output
    max_files = 15
    if original_count > max_files:
        changed_files = changed_files[:max_files]
        output += f"\n⚠️ Showing first {max_files} of {original_count} changed files\n"

    total_diff_size = 0
    for file_path in changed_files:
        # Stop if we're approaching size limits
        if total_diff_size > MAX_FILE_DIFF_SIZE * 10:  # Total limit for all diffs
            output += f"\n\n... (remaining {len(changed_files) -
                                            changed_files.index(file_path)} files truncated)"
            break

        # Get diff for this specific file
        diff_cmd = [
            "git", "diff", "--unified=3", "--no-color",
            f"{from_tag}..{to_tag}", "--", file_path
        ]
        diff_result = subprocess.run(diff_cmd, capture_output=True, text=True,
                                     check=True, encoding='utf-8', errors='replace')

        if diff_result.stdout:
            file_diff = diff_result.stdout.strip()
            if file_diff:
                # Truncate individual file diffs
                if len(file_diff) > MAX_FILE_DIFF_SIZE:
                    file_diff = _truncate_text(file_diff, MAX_FILE_DIFF_SIZE,
                                               "\n... (diff truncated)")

                output += f"\n\n### {file_path}\n\n```diff\n{file_diff}\n```"
                total_diff_size += len(file_diff)

    return output


def _get_first_release_files(to_tag: str) -> str:
    """Get key files for first release."""
    cmd = ["git", "ls-tree", "-r", "--name-only", to_tag]
    result = subprocess.run(cmd, capture_output=True, text=True,
                            check=True, encoding='utf-8', errors='replace')

    if not result.stdout:
        return ""

    files = result.stdout.strip()
    if files:
        main_files = [
            f for f in files.split('\n')
            if f.endswith(('.py', '.yml', '.yaml', '.toml', '.md', '.txt'))
            and not f.startswith('.')
        ][:20]
        return ("\n\n## Key Files in Release\n\n```\n" +
                '\n'.join(main_files) + "\n```")
    return ""


def get_git_log(from_tag: Optional[str] = None, to_tag: str = "HEAD") -> str:
    """Get git log with controlled diff between two tags/commits."""
    try:
        git_output = _get_commit_log(from_tag, to_tag)

        # Get per-file diffs for better context, but with size limits
        try:
            if from_tag:
                diffs = _get_file_diffs(from_tag, to_tag)
                # Combine and check total size
                combined = git_output + diffs
                if len(combined) > MAX_GIT_LOG_LENGTH:
                    # If too long, prioritize commit log over diffs
                    if len(git_output) > MAX_GIT_LOG_LENGTH:
                        git_output = _truncate_text(git_output, MAX_GIT_LOG_LENGTH)
                    else:
                        # Truncate diffs to fit
                        remaining_space = MAX_GIT_LOG_LENGTH - len(git_output)
                        diffs = _truncate_text(diffs, remaining_space)
                    git_output += diffs
                else:
                    git_output = combined
            else:
                first_release_info = _get_first_release_files(to_tag)
                combined = git_output + first_release_info
                if len(combined) > MAX_GIT_LOG_LENGTH:
                    git_output = _truncate_text(combined, MAX_GIT_LOG_LENGTH)
                else:
                    git_output = combined

        except subprocess.CalledProcessError:
            # If diff fails, just continue with the log
            pass

        return git_output
    except subprocess.CalledProcessError as e:
        print(f"Error getting git log: {e}", file=sys.stderr)
        return ""


def generate_release_description(git_log: str, version: str, api_key: str) -> str:
    """Generate release description using OpenAI API."""
    client = openai.OpenAI(api_key=api_key)

    prompt = f"""
    Create a comprehensive and professional release description for version {version} of
    "lanscape" - a Python network scanning tool.

    You have access to complete git history including detailed code diffs.
    Analyze the following data thoroughly:

    {git_log}

    The above contains:
    - Complete commit history with author information and file statistics
    - Full code diffs for every changed file showing exact modifications
    - Context around each change (3 lines before/after)

    ANALYSIS INSTRUCTIONS:
    1. Examine each file diff to understand the technical nature of changes
    2. Look for patterns across commits to identify larger themes
    3. Distinguish between user-facing changes and internal improvements
    4. Identify the scope of impact (core functionality, UI, performance, etc.)
    5. Consolidate related changes into coherent sections

    Pay special attention to:
    - New classes, functions, or modules being added
    - Changes to existing APIs or interfaces
    - Error handling improvements and bug fixes
    - Configuration, workflow, or build system changes
    - UI/UX modifications and user experience improvements
    - Performance optimizations and efficiency gains
    - Documentation and help text updates
    - Test coverage and code quality improvements

    FORMAT YOUR RESPONSE AS:

    **Brief summary paragraph** highlighting the most significant changes and overall impact. You're not trying to sell what changed. Youre just relaying the facts.

    ## 🆕 What's New
    - Major new features and capabilities (be specific about functionality)

    ## ⚡ High-level Improvements
    - Enhancements to existing features
    - Performance optimizations
    - User experience improvements

    ## 🔧 Technical Changes
    - Infrastructure improvements
    - Code quality enhancements
    - Build/deployment changes

    ## 🐛 Bug Fixes
    - Specific issues resolved (if applicable)

    ## ⚠️ Breaking Changes
    - Any changes that might affect existing users (if applicable)

    Be accurate, concise, and professional. You're not trying to sell what changed. Youre just relaying the facts.
    If no significant changes are found, state that clearly.
    """

    # Try GPT-4o first, fallback to other models if needed
    models = [
        {"model": "gpt-4o", "max_tokens": 2000,
            "note": "GPT-4o (full context)"},
        {"model": "gpt-4-turbo-preview", "max_tokens": 1500,
         "note": "GPT-4 Turbo (high context)"},
        {"model": "gpt-4", "max_tokens": 1000, "note": "GPT-4 (standard)"},
        {"model": "gpt-3.5-turbo", "max_tokens": 800,
            "note": "GPT-3.5 Turbo (fallback)"}
    ]

    for model_config in models:
        try:
            print(f"Trying {model_config['note']}...", file=sys.stderr)

            response = client.chat.completions.create(
                model=model_config["model"],
                messages=[
                    {
                        "role": "system",
                        "content": ("You are a technical writer creating release notes "
                                    "for a Python package. Be concise, professional, and "
                                    "focus on user-facing changes. You have access to "
                                    "detailed code diffs - use them to provide accurate, "
                                    "technical insights. You are not trying to market the changes, "
                                    "just relay the facts. Do your best to keep the character "
                                    "count under 10k.")
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=model_config["max_tokens"],
                temperature=0.2
            )

            print(
                f"✓ Successfully used {model_config['note']}", file=sys.stderr)
            return response.choices[0].message.content.strip()

        except Exception as model_error:
            print(
                f"✗ {model_config['note']} failed: {model_error}", file=sys.stderr)
            continue

    # If all models failed, return fallback
    print("✗ All models failed, using fallback description", file=sys.stderr)
    return f"""
## Release v{version}

This release includes the following changes:

{git_log}

For more details, see the commit history.
"""


def main():
    """Main function to generate release notes."""

    if len(sys.argv) < 2:
        print("Usage: python generate_release_notes.py <version> [from_tag]",
              file=sys.stderr)
        print("  version: Version number for the release", file=sys.stderr)
        print("  from_tag: Optional previous tag to compare against", file=sys.stderr)
        print("", file=sys.stderr)
        print("Note: Uses GPT-4o with full context - no truncation limits!",
              file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1].split('/')[-1]  # Extract version number from tag
    from_tag = sys.argv[2] if len(sys.argv) > 2 else None

    # Get API key from environment
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    # Get git log
    git_log = get_git_log(from_tag)
    if not git_log:
        print("No commits found for release notes", file=sys.stderr)
        sys.exit(1)

    # Generate description
    description = generate_release_description(git_log, version, api_key)

    # Append installation/upgrade instructions
    installation_instructions = f"""

## 📦 Installation & Upgrade

### Fresh Installation
```bash
pip install lanscape
```

### Upgrade from Previous Version
```bash
pip install --upgrade lanscape=={version}
```

### Run LANscape
```bash
python -m lanscape
# or simply (experimental):
lanscape
```

### Verify Installation
```bash
python -m lanscape --version
```

For more details and troubleshooting, see the [README](https://github.com/mdennis281/LANscape/blob/main/README.md).
"""

    # Print the complete release notes with final length check
    final_output = description + installation_instructions

    if len(final_output) > MAX_RELEASE_BODY_LENGTH:
        print(
            f"⚠️ Release notes too long ({
                len(final_output)} chars), truncating...",
            file=sys.stderr)
        # Prioritize the AI-generated description over installation instructions
        max_desc_length = MAX_RELEASE_BODY_LENGTH - \
            len(installation_instructions) - 100  # Safety margin
        if max_desc_length > 0:
            description = _truncate_text(description, max_desc_length,
                                         "\n\n... (content truncated due to length limits)")
            final_output = description + installation_instructions
        else:
            # If even that's too long, truncate everything
            final_output = _truncate_text(final_output, MAX_RELEASE_BODY_LENGTH)

        print(f"✓ Truncated to {len(final_output)} characters", file=sys.stderr)

    print(final_output)


if __name__ == "__main__":
    main()
