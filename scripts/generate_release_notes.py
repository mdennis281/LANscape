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
        # First get the commit messages with stats
        if from_tag:
            log_cmd = ["git", "log", "--stat", "--pretty=format:### %s (%an)%n", f"{from_tag}..{to_tag}"]
        else:
            log_cmd = ["git", "log", "--stat", "--pretty=format:### %s (%an)%n", to_tag]
        
        log_result = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
        git_output = log_result.stdout.strip()
        
        # Now get the actual code diffs
        try:
            if from_tag:
                # Get a more concise diff that's better for AI analysis
                diff_cmd = ["git", "diff", "--unified=2", "--no-color", f"{from_tag}..{to_tag}"]
                diff_result = subprocess.run(diff_cmd, capture_output=True, text=True, check=True)
                diff_content = diff_result.stdout.strip()
                
                if diff_content:
                    # Limit diff size to avoid overwhelming the AI (keep first 3000 chars)
                    if len(diff_content) > 3000:
                        diff_content = diff_content[:3000] + "\n\n... (diff truncated for brevity)"
                    
                    git_output += f"\n\n## Code Changes\n\n```diff\n{diff_content}\n```"
            else:
                # For first release, show key files
                file_cmd = ["git", "ls-tree", "-r", "--name-only", to_tag]
                file_result = subprocess.run(file_cmd, capture_output=True, text=True, check=True)
                files = file_result.stdout.strip()
                
                if files:
                    # Show main Python files and configs for context
                    main_files = [f for f in files.split('\n') if f.endswith(('.py', '.yml', '.yaml', '.toml', '.md', '.txt')) and not f.startswith('.')][:20]
                    git_output += f"\n\n## Key Files in Release\n\n```\n" + '\n'.join(main_files) + "\n```"
                
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
    
    Based on the following git commits, file statistics, and actual code changes, analyze and summarize the release:
    
    {git_log}
    
    The above includes:
    - Commit messages with author information
    - File change statistics (lines added/removed)
    - Actual code diffs showing what was modified
    
    Use the code diffs to understand the technical nature of changes. Look for:
    - New functions, classes, or features being added
    - Bug fixes (error handling, corrections)
    - Configuration or workflow changes
    - UI/UX improvements
    - Performance optimizations
    - Documentation updates
    
    Format the response as:
    - Brief introductory paragraph summarizing the release
    - ## What's New (bullet points for major new features)
    - ## Improvements (bullet points for enhancements)
    - ## Bug Fixes (if applicable)
    - ## Breaking Changes (if applicable)
    - ## Technical Details (if there are significant internal changes worth mentioning)
    
    Focus on user-facing impact while being technically accurate. Translate code changes into user benefits when possible.
    
    Keep it professional and concise. Use markdown formatting for readability.
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
    print("---")
    print("# Context (git log):\n")
    print(git_log)
    
    # Generate description
    description = generate_release_description(git_log, version, api_key)
    
    
    print("---")
    print("# Release Description:\n")
    print(description)


if __name__ == "__main__":
    main()