#!/usr/bin/# Configuration
MAX_LINES_PER_FILE = None  # No limit - let the model handle it
MAX_TOTAL_DIFF_SIZE = None  # No limit - use model's full context window python3
"""
Generate release notes using OpenAI API based on git commit history.
"""

import os
import sys
import subprocess
import openai
from typing import Optional

# Configuration
MAX_LINES_PER_FILE = 50  # Maximum lines to show per file diff
MAX_TOTAL_DIFF_SIZE = 5000  # Maximum total diff size to avoid overwhelming AI


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
        
        # Get per-file diffs for better context
        try:
            if from_tag:
                git_output += f"\n\n## Code Changes by File\n"
                
                # First get list of changed files
                changed_files_cmd = ["git", "diff", "--name-only", f"{from_tag}..{to_tag}"]
                changed_files_result = subprocess.run(changed_files_cmd, capture_output=True, text=True, check=True)
                changed_files = [f.strip() for f in changed_files_result.stdout.strip().split('\n') if f.strip()]
                
                total_diff_size = 0
                
                for file_path in changed_files:
                    # Get diff for this specific file
                    file_diff_cmd = ["git", "diff", "--unified=3", "--no-color", f"{from_tag}..{to_tag}", "--", file_path]
                    file_diff_result = subprocess.run(file_diff_cmd, capture_output=True, text=True, check=True)
                    file_diff = file_diff_result.stdout.strip()
                    
                    if file_diff:
                        git_output += f"\n\n### {file_path}\n\n```diff\n{file_diff}\n```"
                        
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
    Create a comprehensive and professional release description for version {version} of "lanscape" - a Python network scanning tool.
    
    You have access to complete git history including detailed code diffs. Analyze the following data thoroughly:
    
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
    
    **Brief summary paragraph** highlighting the most significant changes and overall impact.
    
    ## 🆕 What's New
    - Major new features and capabilities (be specific about functionality)
    
    ## ⚡ Improvements  
    - Enhancements to existing features
    - Performance optimizations
    - User experience improvements
    
    ## 🐛 Bug Fixes
    - Specific issues resolved (if applicable)
    
    ## 🔧 Technical Changes
    - Infrastructure improvements
    - Code quality enhancements
    - Build/deployment changes
    
    ## ⚠️ Breaking Changes
    - Any changes that might affect existing users (if applicable)
    
    Be technically accurate but translate code changes into user benefits where possible. Use emojis and clear formatting for readability.
    """
    
    # Try GPT-4o first, fallback to other models if needed
    models_to_try = [
        {"model": "gpt-4o", "max_tokens": 2000, "context_note": "GPT-4o (full context)"},
        {"model": "gpt-4-turbo-preview", "max_tokens": 1500, "context_note": "GPT-4 Turbo (high context)"},
        {"model": "gpt-4", "max_tokens": 1000, "context_note": "GPT-4 (standard)"},
        {"model": "gpt-3.5-turbo", "max_tokens": 800, "context_note": "GPT-3.5 Turbo (fallback)"}
    ]
    
    for model_config in models_to_try:
        try:
            print(f"Trying {model_config['context_note']}...", file=sys.stderr)
            
            response = client.chat.completions.create(
                model=model_config["model"],
                messages=[
                    {"role": "system", "content": "You are a technical writer creating release notes for a Python package. Be concise, professional, and focus on user-facing changes. You have access to detailed code diffs - use them to provide accurate, technical insights."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=model_config["max_tokens"],
                temperature=0.2
            )
            
            print(f"✓ Successfully used {model_config['context_note']}", file=sys.stderr)
            return response.choices[0].message.content.strip()
            
        except Exception as model_error:
            print(f"✗ {model_config['context_note']} failed: {model_error}", file=sys.stderr)
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
    global MAX_LINES_PER_FILE
    
    if len(sys.argv) < 2:
        print("Usage: python generate_release_notes.py <version> [from_tag]", file=sys.stderr)
        print("  version: Version number for the release", file=sys.stderr)
        print("  from_tag: Optional previous tag to compare against", file=sys.stderr)
        print("", file=sys.stderr)
        print("Note: Uses GPT-4o with full context - no truncation limits!", file=sys.stderr)
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