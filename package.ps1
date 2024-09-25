# Run Python unit tests
$unittestResult = python -m unittest

# Check if the tests succeeded
if ($LASTEXITCODE -eq 0) {
    # Remove files in dist directory
    Remove-Item -Path .\dist\* -Recurse -Force

    # Upgrade pip and build the package
    py -m pip install --upgrade pip
    py -m pip install --upgrade build
    py -m build

    # Upgrade twine and upload the package
    py -m pip install --upgrade twine
    py -m twine upload --repository pypi dist/*
} else {
    Write-Host "Unit tests failed. Exiting script." -ForegroundColor Red
    exit $LASTEXITCODE
}
