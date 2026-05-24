# Create a Python virtual environment and install dependencies.
#
# Usage:
#   .\setup.ps1

$ErrorActionPreference = "Stop"
$VenvDir = ".venv"

if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment in $VenvDir..."
    python -m venv $VenvDir
}

Write-Host "Installing dependencies..."
& "$VenvDir\Scripts\pip.exe" install --upgrade pip --quiet
& "$VenvDir\Scripts\pip.exe" install -r requirements.txt --quiet

Write-Host ""
Write-Host "Setup complete."
Write-Host "Activate the virtual environment with:"
Write-Host "  .\$VenvDir\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Then run:"
Write-Host "  python main.py --help"
