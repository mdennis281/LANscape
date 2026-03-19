# LANscape Integration Test Runner (Windows)
#
# Usage:
#   .\tests\integration\run.ps1           # Run tests, then cleanup
#   .\tests\integration\run.ps1 -Keep     # Keep containers running after tests
#   .\tests\integration\run.ps1 -Build    # Force rebuild scanner image

param(
    [switch]$Keep,
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ScriptDir "docker-compose.yml"

function Invoke-Cleanup {
    if (-not $Keep) {
        Write-Host "`n-- Cleaning up --"
        docker compose -f $ComposeFile down -v --remove-orphans 2>$null
    } else {
        Write-Host "`n-- Containers kept running --"
        Write-Host "   Stop with: docker compose -f $ComposeFile down"
    }
}

try {
    # Build
    Write-Host "-- Building service containers --"
    $buildArgs = @("-f", $ComposeFile, "build")
    if ($Build) { $buildArgs += "--build" }
    docker compose @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    # Start services
    Write-Host "`n-- Starting service containers --"
    docker compose -f $ComposeFile up -d
    if ($LASTEXITCODE -ne 0) { throw "Failed to start services" }

    # Wait for healthy
    Write-Host "`n-- Waiting for services to be healthy --"
    $services = docker compose -f $ComposeFile ps --services | Where-Object { $_ -ne "scanner" }
    foreach ($svc in $services) {
        Write-Host -NoNewline "  Waiting for ${svc}..."
        $timeout = 60
        while ($timeout -gt 0) {
            $status = docker inspect --format='{{.State.Health.Status}}' "lanscape-test-$svc" 2>$null
            if ($status -eq "healthy") {
                Write-Host " ready"
                break
            }
            Start-Sleep -Seconds 1
            $timeout--
        }
        if ($timeout -eq 0) {
            Write-Host " TIMEOUT"
            Write-Warning "$svc did not become healthy in time"
        }
    }

    # Run tests
    Write-Host "`n-- Running integration tests --"
    docker compose -f $ComposeFile run --rm scanner
    $testExit = $LASTEXITCODE

    # Show results
    $reportPath = Join-Path $ScriptDir "results\report.txt"
    if (Test-Path $reportPath) {
        Write-Host "`n-- Test Results --"
        Get-Content $reportPath
    }

    exit $testExit
}
finally {
    Invoke-Cleanup
}
