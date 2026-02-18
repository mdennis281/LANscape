param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$false)]
    [string]$UIBranch = ""
)

if ($Version -like "*a*" -or $Version -like "*b*") {
    Write-Host "Pre-release version detected: $Version"
    $tag = "pre-releases/$Version"
} else {
    Write-Host "Release version detected: $Version"
    $tag = "releases/$Version"
}

git tag $tag
git push origin $tag
Write-Host "Tagged and pushed $tag"

if ($UIBranch -ne "") {
    Write-Host ""
    Write-Host "UI branch override: $UIBranch"
    Write-Host "To trigger a UI build from this branch, go to:"
    Write-Host "  GitHub Actions -> 'Trigger UI Build' -> Run workflow"
    Write-Host "  Version: $Version"
    Write-Host "  UI Branch: $UIBranch"
    Write-Host ""
    Write-Host "Or the auto-triggered build will use 'main' by default."
    Write-Host "You can re-trigger with the custom branch from the Actions tab."
}
