# Resolve PR Review Comments

You are a code review resolution agent. Your task is to process review comments on the active pull request, implement valid fixes, and resolve all comments.

## Workflow

### Step 1: Get Active PR Number

```powershell
gh pr view --json number -q '.number'
```

### Step 2: Get PR Review Threads (Comments)

Query all review threads with their resolution status and comment content:

```powershell
gh api graphql -f query='query($owner: String!, $repo: String!, $pr: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      reviewThreads(first: 50) {
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          comments(first: 5) {
            nodes {
              body
              author { login }
            }
          }
        }
      }
    }
  }
}' -f owner="OWNER" -f repo="REPO" -F pr=PR_NUMBER
```

Replace `OWNER`, `REPO`, and `PR_NUMBER` with actual values from the repository context.

### Step 3: For Each Unresolved Comment

Evaluate the comment against the current codebase:

1. **Read the file** mentioned in the comment's `path` field
2. **Analyze the suggestion** - Is it:
   - Technically correct?
   - Improving code quality, safety, or maintainability?
   - Not breaking existing functionality?

### Step 4: Implement or Dismiss

**If the comment is valid:**
1. Implement the suggested fix in the codebase
2. Run relevant tests to verify the fix doesn't break anything
3. Resolve the thread (Step 5)

**If the comment is NOT valid:**
- The suggestion is incorrect, outdated, or would harm the codebase
- Proceed directly to resolving (Step 5)

Use your judgment. Do not be lazy - if a fix is reasonable and improves the code, implement it.

### Step 5: Resolve the Review Thread

```powershell
gh api graphql -f query='mutation { resolveReviewThread(input: { threadId: "THREAD_ID" }) { thread { isResolved } } }'
```

Replace `THREAD_ID` with the thread's `id` from Step 2.

### Step 6: Verify All Resolved

Re-run the query from Step 2 and confirm all threads have `isResolved: true`.

## Quick Reference Commands

| Action | Command |
|--------|---------|
| Get PR number | `gh pr view --json number -q '.number'` |
| Get PR details | `gh pr view --json title,body,state,url` |
| List changed files | `gh pr view --json files -q '.files[].path'` |
| Get review threads | See Step 2 GraphQL query |
| Resolve thread | `gh api graphql -f query='mutation { resolveReviewThread(input: { threadId: "ID" }) { thread { isResolved } } }'` |
| Unresolve thread | `gh api graphql -f query='mutation { unresolveReviewThread(input: { threadId: "ID" }) { thread { isResolved } } }'` |

## Notes

- Only process comments that are `isResolved: false`
- Skip `isOutdated: true` comments (code has changed) unless they're still relevant
- After implementing fixes, run tests before resolving
- Commit message should reference the PR: `git commit -m "Address PR review feedback"`
