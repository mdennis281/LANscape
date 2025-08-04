#!/bin/bash

# Usage:
# ./package.sh
# ./package.sh --skip-tests
# ./package.sh --skip-upload
# ./package.sh --skip-tests --skip-upload

SKIP_TESTS=false
SKIP_UPLOAD=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-upload)
            SKIP_UPLOAD=true
            shift
            ;;
    esac
done


if [ "$SKIP_TESTS" = false ]; then
    # Run Python unit tests
    python3 -m unittest

    # Check if the tests succeeded
    if [ $? -ne 0 ]; then
        echo "Unit tests failed. Exiting script." >&2
        exit 1
    fi
fi

# Remove files in dist directory
rm -rf dist
rm -rf ./**/*.egg-info

# Upgrade pip and build the package
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade build
python3 -m build

if [ "$SKIP_UPLOAD" = false ]; then
    # Upgrade twine and upload the package
    python3 -m pip install --upgrade twine

    python3 -m twine check dist/*
    python3 -m twine upload --repository pypi dist/*
fi
