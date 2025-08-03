# Usage:
# .\package.ps1 
# .\package.ps1 -SkipTests
# .\package.ps1  -SkipUpload
# .\package.ps1  -SkipUpload -SkipTests

param (
    [switch]$SkipTests,
    [switch]$SkipUpload
)

Set-Location ../

if (-not $SkipTests) {
    # Run Python unit tests
    python -m unittest

    # Check if the tests succeeded
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Unit tests failed. Exiting script." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}


# Remove files in dist directory
Remove-Item -Path dist -Recurse -Force
Remove-Item -Path ./**/*.egg-info -Recurse -Force

# Upgrade pip and build the package
py -m pip install --upgrade pip
py -m pip install --upgrade build
py -m build

if (-not $SkipUpload) {
    # Upgrade twine and upload the package
    py -m pip install --upgrade twine

    py -m twine check dist/*
    py -m twine upload --repository pypi dist/*
}
