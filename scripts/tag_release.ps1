param(
    [Parameter(Mandatory=$false)]
    [string]$Version = "",

    [Parameter(Mandatory=$false)]
    [string]$UIBranch = ""
)

# Fetch tags so we have the latest
git fetch --tags 2>$null

# Find last release tag (releases/vX.Y.Z)
$lastRelease = git tag --list 'releases/*' --sort=-version:refname 2>$null | Select-Object -First 1
if ($lastRelease) { $lastRelease = $lastRelease -replace '^releases/', '' } else { $lastRelease = '(none)' }

# Find last pre-release tag (pre-releases/*) covering alpha, beta, rc
$lastPreRelease = git tag --list 'pre-releases/*' --sort=-version:refname 2>$null | Select-Object -First 1
if ($lastPreRelease) { $lastPreRelease = $lastPreRelease -replace '^pre-releases/', '' } else { $lastPreRelease = '(none)' }

# Find the most recent alpha
$lastAlpha = git tag --list 'pre-releases/*a*' --sort=-version:refname 2>$null | Select-Object -First 1
if ($lastAlpha) { $lastAlpha = $lastAlpha -replace '^pre-releases/', '' } else { $lastAlpha = '(none)' }

# Find the most recent beta
$lastBeta = git tag --list 'pre-releases/*b*' --sort=-version:refname 2>$null | Select-Object -First 1
if ($lastBeta) { $lastBeta = $lastBeta -replace '^pre-releases/', '' } else { $lastBeta = '(none)' }

# Find the most recent RC
$lastRC = git tag --list 'pre-releases/*rc*' --sort=-version:refname 2>$null | Select-Object -First 1
if ($lastRC) { $lastRC = $lastRC -replace '^pre-releases/', '' } else { $lastRC = '(none)' }

Write-Host ""
Write-Host "=== Last Tagged Versions ==="
Write-Host "  Release    : $lastRelease"
Write-Host "  Pre-release: $lastPreRelease"
Write-Host "    Alpha    : $lastAlpha"
Write-Host "    Beta     : $lastBeta"
Write-Host "    RC       : $lastRC"
Write-Host ""

if ($Version -eq "") {
    $Version = Read-Host "Enter new version to tag"
}

if ($Version -eq "") {
    Write-Host "No version provided. Aborting."
    exit 1
}

if ($UIBranch -eq "") {
    Write-Host ""
    $UIBranch = Read-Host "Enter UI branch to build from [main]"
    if ($UIBranch -eq "") { $UIBranch = "main" }
}

Write-Host ""

if ($UIBranch -eq "main") {
    # Standard path: push git tag, auto-triggers package.yml with ui_branch=main
    if ($Version -like "*a*" -or $Version -like "*b*" -or $Version -like "*rc*") {
        Write-Host "Pre-release version detected: $Version"
        $tag = "pre-releases/$Version"
    } else {
        Write-Host "Release version detected: $Version"
        $tag = "releases/$Version"
    }
    git tag $tag
    git push origin $tag
    Write-Host "Tagged and pushed $tag"
} else {
    # Custom UI branch: trigger workflow_dispatch via gh CLI.
    # The workflow creates the git tag and triggers the UI build with the custom branch.
    Write-Host "Custom UI branch: $UIBranch"
    Write-Host "Triggering release workflow via GitHub CLI..."

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: GitHub CLI (gh) is not installed or not in PATH."
        Write-Host "Install it from https://cli.github.com/ then run: gh auth login"
        exit 1
    }

    gh workflow run package.yml --field "version=$Version" --field "ui_branch=$UIBranch"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to trigger workflow. Ensure you are authenticated: gh auth login"
        exit 1
    }

    Write-Host ""
    Write-Host "Workflow dispatched successfully!"
    Write-Host "  Version  : $Version"
    Write-Host "  UI Branch: $UIBranch"
    Write-Host ""
    Write-Host "The workflow will create the git tag and trigger the UI build."
}
