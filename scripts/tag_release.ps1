param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

$tag = "releases/$Version"

git tag $tag
git push origin $tag
Write-Host "Tagged and pushed $tag"
