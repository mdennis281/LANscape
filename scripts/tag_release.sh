#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

if [[ "$1" == *a* || "$1" == *b* ]]; then
    echo "Pre-release version detected: $1"
    TAG="pre-releases/$1"
else
    echo "Release version detected: $1"
    TAG="releases/$1"
fi

git tag "$TAG"
git push origin "$TAG"
echo "Tagged and pushed $TAG"
