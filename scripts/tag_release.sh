#!/bin/bash
set -e

VERSION=""
UI_BRANCH=""

# Parse optional positional version and --ui-branch flag
if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
    VERSION="$1"
    shift
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --ui-branch)
            UI_BRANCH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Fetch tags so we have the latest
git fetch --tags 2>/dev/null || true

# Find last release tag
LAST_RELEASE=$(git tag --list 'releases/*' --sort=-version:refname 2>/dev/null | head -1)
LAST_RELEASE=${LAST_RELEASE#releases/}
[ -z "$LAST_RELEASE" ] && LAST_RELEASE="(none)"

# Find last pre-release tag
LAST_PRE=$(git tag --list 'pre-releases/*' --sort=-version:refname 2>/dev/null | head -1)
LAST_PRE=${LAST_PRE#pre-releases/}
[ -z "$LAST_PRE" ] && LAST_PRE="(none)"

# Find last alpha
LAST_ALPHA=$(git tag --list 'pre-releases/*a*' --sort=-version:refname 2>/dev/null | head -1)
LAST_ALPHA=${LAST_ALPHA#pre-releases/}
[ -z "$LAST_ALPHA" ] && LAST_ALPHA="(none)"

# Find last beta
LAST_BETA=$(git tag --list 'pre-releases/*b*' --sort=-version:refname 2>/dev/null | head -1)
LAST_BETA=${LAST_BETA#pre-releases/}
[ -z "$LAST_BETA" ] && LAST_BETA="(none)"

# Find last RC
LAST_RC=$(git tag --list 'pre-releases/*rc*' --sort=-version:refname 2>/dev/null | head -1)
LAST_RC=${LAST_RC#pre-releases/}
[ -z "$LAST_RC" ] && LAST_RC="(none)"

echo ""
echo "=== Last Tagged Versions ==="
echo "  Release    : $LAST_RELEASE"
echo "  Pre-release: $LAST_PRE"
echo "    Alpha    : $LAST_ALPHA"
echo "    Beta     : $LAST_BETA"
echo "    RC       : $LAST_RC"
echo ""

if [ -z "$VERSION" ]; then
    read -rp "Enter new version to tag: " VERSION
fi

if [ -z "$VERSION" ]; then
    echo "No version provided. Aborting."
    exit 1
fi

if [ -z "$UI_BRANCH" ]; then
    echo ""
    read -rp "Enter UI branch to build from [main]: " UI_BRANCH
    [ -z "$UI_BRANCH" ] && UI_BRANCH="main"
fi

echo ""

if [ "$UI_BRANCH" = "main" ]; then
    # Standard path: push git tag, auto-triggers package.yml with ui_branch=main
    if [[ "$VERSION" == *a* || "$VERSION" == *b* || "$VERSION" == *rc* ]]; then
        echo "Pre-release version detected: $VERSION"
        TAG="pre-releases/$VERSION"
    else
        echo "Release version detected: $VERSION"
        TAG="releases/$VERSION"
    fi
    git tag "$TAG"
    git push origin "$TAG"
    echo "Tagged and pushed $TAG"
else
    # Custom UI branch: trigger workflow_dispatch via gh CLI.
    # The workflow creates the git tag and triggers the UI build with the custom branch.
    echo "Custom UI branch: $UI_BRANCH"
    echo "Triggering release workflow via GitHub CLI..."

    if ! command -v gh &>/dev/null; then
        echo "ERROR: GitHub CLI (gh) is not installed or not in PATH."
        echo "Install it from https://cli.github.com/ then run: gh auth login"
        exit 1
    fi

    gh workflow run package.yml --field "version=$VERSION" --field "ui_branch=$UI_BRANCH"

    echo ""
    echo "Workflow dispatched successfully!"
    echo "  Version  : $VERSION"
    echo "  UI Branch: $UI_BRANCH"
    echo ""
    echo "The workflow will create the git tag and trigger the UI build."
fi
