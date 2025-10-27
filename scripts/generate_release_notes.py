#!/usr/bin/env python3
"""
Generate release notes using OpenAI API based on git commit history.
"""

import os
import sys
import subprocess
import openai
from typing import Optional


def get_git_log(from_tag: Optional[str] = None, to_tag: str = "HEAD") -> str:
    """Get git log with full diff between two tags/commits."""
    try:
        if from_tag:
            # Get commits and diffs between from_tag and to_tag
            cmd = ["git", "log", "--stat", "--pretty=format:### %s (%an)%n", f"{from_tag}..{to_tag}"]
        else:
            # Get all commits and diffs up to to_tag (for first release)
            cmd = ["git", "log", "--stat", "--pretty=format:### %s (%an)%n", to_tag]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        git_output = result.stdout.strip()
        
        # If we want even more detail, get the actual diff
        try:
            if from_tag:
                diff_cmd = ["git", "diff", "--name-status", f"{from_tag}..{to_tag}"]
            else:
                # For first release, show all files
                diff_cmd = ["git", "ls-tree", "-r", "--name-only", to_tag]
            
            diff_result = subprocess.run(diff_cmd, capture_output=True, text=True, check=True)
            file_changes = diff_result.stdout.strip()
            
            if file_changes:
                git_output += f"\n\n**Files Changed:**\n```\n{file_changes}\n```"
                
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
    Please create a concise and professional release description for version {version} of the "lanscape" Python network scanning tool.
    
    Based on the following git commits and file changes, summarize the key changes, improvements, and new features:
    
    {git_log}
    
    The above includes both commit messages and file statistics showing what was modified. Use this information to understand the scope and nature of changes.
    
    Format the response as:
    - A brief introductory paragraph summarizing the release
    - ## What's New (bullet points for major new features)
    - ## Improvements (bullet points for enhancements)
    - ## Bug Fixes (if applicable)
    - ## Breaking Changes (if applicable)
    - ## Technical Details (if there are significant internal changes worth mentioning)
    
    Focus on user-facing changes and improvements. Use the file change statistics to understand which areas of the codebase were modified (UI, core libraries, tests, etc.) and mention these areas in context.
    
    Keep it professional and user-focused. Don't mention trivial commits like "fix typos" unless they're part of larger improvements.
    
    Use full markdown formatting for readability including headers, lists, and code formatting where appropriate.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a technical writer creating release notes for a Python package. Be concise, professional, and focus on user-facing changes."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.3
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        print(f"Error generating description with OpenAI: {e}", file=sys.stderr)
        # Return fallback description
        return f"""
## Release v{version}

This release includes the following changes:

{git_log}

For more details, see the commit history.
"""


def main():
    """Main function to generate release notes."""
    if len(sys.argv) < 2:
        print("Usage: python generate_release_notes.py <version> [from_tag]", file=sys.stderr)
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
        
    # Show context (git log) then a divider before the generated description
    print("\n" + "=" * 80)
    print("Context (git log):\n")
    print(git_log)
    
    # Generate description
    description = generate_release_description(git_log, version, api_key)
    
    
    print("\n" + "=" * 80)
    print("Release Description:\n")
    print(description)


if __name__ == "__main__":
    main()