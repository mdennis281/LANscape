---
agent: agent
---
Generate a summary of the current branch's diff off of main. first determine through git checkout if we are on main or not.

if on main, look at uncommitted or staged changes.

realistically break the changes into 3 categories

committed diff off of main (assuming checkout to a non main branch)
staged diff
unstaged diff

once you have context for each of these, summarize the new functionality in each and report back to the user.