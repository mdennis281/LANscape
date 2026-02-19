#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version> [--ui-branch <branch>]"
    exit 1
fi

VERSION="$1"
UI_BRANCH=""

# Parse optional --ui-branch flag
shift
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

if [ -n "$UI_BRANCH" ]; then
    echo ""
    echo "UI branch override: $UI_BRANCH"
    echo "To trigger a UI build from this branch, go to:"
    echo "  GitHub Actions -> 'Trigger UI Build' -> Run workflow"
    echo "  Version: $VERSION"
    echo "  UI Branch: $UI_BRANCH"
    echo ""
    echo "Or the auto-triggered build will use 'main' by default."
    echo "You can re-trigger with the custom branch from the Actions tab."
fi
