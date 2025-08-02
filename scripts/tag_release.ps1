param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

if ($Version -contains "a" -or $Version -contains "b") {
    Write-Host "Pre-release version detected: $Version"
    $tag = "pre-releases/$Version"
} else {
    Write-Host "Release version detected: $Version"
    $tag = "releases/$Version"
}

git tag $tag
git push origin $tag
Write-Host "Tagged and pushed $tag"
