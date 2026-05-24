# Update all installed VS Code extensions to their latest Marketplace versions.
#
# Usage:
#   .\update-extensions.ps1
#   .\update-extensions.ps1 -CodeBinary "code-insiders"
param(
    [string]$CodeBinary = "code"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command $CodeBinary -ErrorAction SilentlyContinue)) {
    Write-Error "Error: '$CodeBinary' not found. Use -CodeBinary if using a non-standard install."
    exit 1
}

$extensions = @(& $CodeBinary --list-extensions 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to list extensions."
    exit 1
}

$total = $extensions.Count
$count = 0
$failed = @()

Write-Host "Updating $total extensions..."
Write-Host ""

foreach ($ext in $extensions) {
    $count++
    if ($ext -notmatch '^[a-zA-Z0-9._-]+$') {
        Write-Host "WARNING: skipping invalid extension ID: $ext" -ForegroundColor Yellow
        continue
    }
    Write-Host -NoNewline "[$count/$total] $ext ... "
    & $CodeBinary --install-extension $ext --force 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "ok"
    } else {
        Write-Host "FAILED"
        $failed += $ext
    }
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "All $total extensions updated successfully."
} else {
    Write-Host "$($failed.Count) extension(s) failed to update:"
    foreach ($f in $failed) { Write-Host "  - $f" }
    exit 1
}

Write-Host ""
Write-Host "Restart VS Code to apply the updates."
Write-Host "The old versions remain active until VS Code relaunches."
