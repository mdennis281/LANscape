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
    """Get git log between two tags/commits."""
    try:
        if from_tag:
            # Get commits between from_tag and to_tag
            cmd = ["git", "log", "--oneline", "--pretty=format:- %s (%an)", f"{from_tag}..{to_tag}"]
        else:
            # Get all commits up to to_tag (for first release)
            cmd = ["git", "log", "--oneline", "--pretty=format:- %s (%an)", to_tag]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting git log: {e}", file=sys.stderr)
        return ""


def generate_release_description(git_log: str, version: str, api_key: str) -> str:
    """Generate release description using OpenAI API."""
    client = openai.OpenAI(api_key=api_key)
    
    prompt = f"""
    Please create a concise and professional release description for version {version} of the "lanscape" Python network scanning tool.
    
    Based on the following git commits, summarize the key changes, improvements, and new features:
    
    {git_log}
    
    Format the response as:
    - A brief introductory paragraph
    - Bullet points for major changes/features
    - Any breaking changes (if applicable)
    - Installation/upgrade notes if relevant
    
    Keep it professional and user-focused. Don't mention internal commits like "fix typos" or "update dependencies" unless they're significant.
    
    Ensure you make full use of markdown formatting for readability.
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
## Release v{version.split('/')[-1]}

This release includes the following changes:

{git_log}

For more details, see the commit history.
"""


def main():
    """Main function to generate release notes."""
    if len(sys.argv) < 2:
        print("Usage: python generate_release_notes.py <version> [from_tag]", file=sys.stderr)
        sys.exit(1)
    
    version = sys.argv[1]
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
    
    # Output the description
    print(description)


if __name__ == "__main__":
    main()