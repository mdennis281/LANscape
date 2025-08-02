#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

TAG="releases/$1"

git tag "$TAG"
git push origin "$TAG"
echo "Tagged and pushed $TAG"
