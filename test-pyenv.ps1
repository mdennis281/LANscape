# Define the Python versions you want to test
$pythonVersions = @(8..13 | ForEach-Object { "3.$_" })

# Define the project directory
$projectDir = (Get-Location).Path
$requirementsFile = Join-Path -Path $projectDir -ChildPath "requirements.txt"
$testFile = Join-Path -Path $projectDir -ChildPath "test.py"

# Check if pyenv is installed
if (-not (Get-Command "pyenv" -ErrorAction SilentlyContinue)) {
    Write-Output "Pyenv is not installed. Please install pyenv before running this script."
    exit
}

# Get the exact installed versions
$installedVersions = pyenv versions --bare | ForEach-Object { $_.Trim() }

foreach ($version in $pythonVersions) {
    # Find the exact match for the desired Python version
    $exactVersion = $installedVersions | Where-Object { $_ -match "^$version\.\d+$" } | Sort-Object -Descending | Select-Object -First 1

    if (-not $exactVersion) {
        Write-Output "Python $version is not installed via pyenv. Installing..."
        pyenv install $version
        $installedVersions = pyenv versions --bare | ForEach-Object { $_.Trim() }
        $exactVersion = $installedVersions | Where-Object { $_ -match "^$version\.\d+$" } | Sort-Object -Descending | Select-Object -First 1
    }

    Write-Output "`n--- Testing Python $exactVersion ---"
    
    # Set the exact version for pyenv
    pyenv shell $exactVersion
    $pythonExec = pyenv which python

    # Create a virtual environment
    $venvPath = Join-Path -Path $projectDir -ChildPath ".venv_$exactVersion"
    
    & $pythonExec -m venv $venvPath
    
    if (-not (Test-Path $venvPath)) {
        Write-Output "Failed to create virtual environment for Python $exactVersion."
        exit
    }

    

    # Activate the virtual environment
    & "$venvPath/Scripts/Activate.ps1"

    # Validate running correct python version
    $reportedVersion = python -V
    if ($exactVersion -in $reportedVersion) {
        Write-Output "Failed to activate python version. '$reportedVersion' != '$exactVersion'"
        break
    }
    Write-Output "Validated venv version is $reportedVersion"

    # Install dependencies
    if (Test-Path $requirementsFile) {
        Write-Output "Installing dependencies..."
        pip install -r $requirementsFile
        if ($LASTEXITCODE -ne 0) {
            Write-Output "Failed to install dependencies for Python $exactVersion."
            deactivate
            exit
        }
    } else {
        Write-Output "No requirements.txt found."
    }

    # Run test.py
    Write-Output "Running test.py with Python $exactVersion..."
    python $testFile
    if ($LASTEXITCODE -eq 0) {
        Write-Output "Python $exactVersion : Test succeeded."
        # Clean up by removing the virtual environment
        Remove-Item -Recurse -Force $venvPath
    } else {
        Write-Output "Python $exactVersion : Test failed. Stopping further tests."
        # Deactivate and break the loop
        deactivate
        break
    }

    # Deactivate virtual environment after each run
    deactivate
}

# Reset pyenv shell to default
pyenv shell --unset

Write-Output "`nTesting completed."
