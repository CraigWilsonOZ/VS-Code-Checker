# Export all installed VS Code extensions as .vsix files for offline installation.
# Reads the VS Code extensions catalog to get exact versions and target platforms.
#
# Usage:
#   .\export-extensions.ps1                          # saves to .\vscode-extensions-export\
#   .\export-extensions.ps1 -OutputDir .\my-backup   # saves to a custom directory
#
# Output:
#   <dir>\vsix\                             - one .vsix file per extension (universal + platform-specific)
#   <dir>\install.ps1                       - offline vsix installer (no internet needed)
#   <dir>\install-from-marketplace.ps1      - online installer (resets install_source to gallery)
param(
    [string]$OutputDir  = ".\vscode-extensions-export",
    [string]$CodeBinary = "code"
)

$ErrorActionPreference = "Stop"

$VsixDir            = Join-Path $OutputDir "vsix"
$InstallScript      = Join-Path $OutputDir "install.ps1"
$MarketplaceScript  = Join-Path $OutputDir "install-from-marketplace.ps1"
$Catalog       = Join-Path $env:USERPROFILE ".vscode\extensions\extensions.json"

# ── Preflight ──────────────────────────────────────────────────────────────────

if (-not (Get-Command $CodeBinary -ErrorAction SilentlyContinue)) {
    Write-Error "Error: '$CodeBinary' not found. Use -CodeBinary if using a non-standard install."
    exit 1
}
if (-not (Test-Path $Catalog)) {
    Write-Error "Error: extensions catalog not found at $Catalog"
    exit 1
}

New-Item -ItemType Directory -Force -Path $VsixDir | Out-Null

# ── Parse catalog ──────────────────────────────────────────────────────────────

$catalogJson = Get-Content $Catalog -Raw | ConvertFrom-Json

$extensions = [System.Collections.Generic.List[PSObject]]::new()
$extIds     = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new()
$validExtensionIdPattern = '^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9][A-Za-z0-9_-]*$'

foreach ($entry in $catalogJson) {
    $extId = ($entry.identifier.id ?? "").ToLower()
    if (-not $extId) { continue }
    if ($extId -notmatch $validExtensionIdPattern) {
        Write-Warning "skipping invalid extension id '$extId'"
        continue
    }
    if (-not $seen.Add($extId)) { continue }

    $version = $entry.metadata.version
    if (-not $version) {
        # Fall back to parsing version from relativeLocation
        $loc = $entry.relativeLocation ?? ""
        if ($loc -match '-(\d+\.\d+[\.\d]*)') {
            $version = $Matches[1]
        }
    }

    $platform = $entry.metadata.targetPlatform
    if ($platform -eq "undefined" -or $null -eq $platform) { $platform = "" }

    $validPlatforms = @("linux-x64","linux-arm64","linux-armhf","darwin-arm64","darwin-x64","win32-x64","win32-arm64","win32-ia32","alpine-arm64","alpine-x64")
    if ($platform -and $platform -notin $validPlatforms) {
        Write-Host "WARNING: skipping unknown platform '$platform' for $extId"
        $platform = ""
    }

    if ($extId -and $version) {
        $extensions.Add([PSCustomObject]@{
            ExtId    = $extId
            Version  = $version
            Platform = $platform
        })
    }
}

$total = $extensions.Count
Write-Host "Found $total extensions in catalog."
Write-Host ""

# ── Download helper ────────────────────────────────────────────────────────────

function Invoke-VsixDownload {
    param([string]$Filename, [string]$Url)

    $dest = Join-Path $VsixDir $Filename

    if (Test-Path $dest) {
        $bytes = [System.IO.File]::ReadAllBytes($dest)
        if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B `
                                 -and $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
            Write-Host ("  {0,-60} already downloaded" -f $Filename)
            return $true
        }
        Remove-Item $dest -Force
    }

    Write-Host -NoNewline ("  {0,-60} " -f $Filename)
    try {
        Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing -ErrorAction Stop

        $bytes = [System.IO.File]::ReadAllBytes($dest)
        if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B `
                                 -and $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
            $sizeMB = [math]::Round((Get-Item $dest).Length / 1MB, 1)
            Write-Host "ok (${sizeMB}MB)"
            return $true
        }
        Remove-Item $dest -Force
        Write-Host "FAILED (invalid zip)"
        return $false
    } catch {
        if (Test-Path $dest) { Remove-Item $dest -Force }
        Write-Host "FAILED ($($_.Exception.Message))"
        return $false
    }
}

# ── Download each extension ────────────────────────────────────────────────────

$failed = [System.Collections.Generic.List[string]]::new()
$count = 0

foreach ($ext in $extensions) {
    $count++
    $extIds.Add($ext.ExtId)
    $publisher = $ext.ExtId.Split(".")[0]
    $name      = $ext.ExtId.Substring($publisher.Length + 1)
    $baseUrl   = "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/$publisher/vsextensions/$name/$($ext.Version)/vspackage"

    Write-Host ("[{0,3}/{1}] {2} v{3}" -f $count, $total, $ext.ExtId, $ext.Version)

    # Always download the universal build
    if (-not (Invoke-VsixDownload "$($ext.ExtId)-$($ext.Version).vsix" $baseUrl)) {
        $failed.Add("$($ext.ExtId)@$($ext.Version) (universal)")
    }

    # Also download the platform-specific build if this extension has one
    if ($ext.Platform) {
        $platformUrl = "$baseUrl`?targetPlatform=$($ext.Platform)"
        if (-not (Invoke-VsixDownload "$($ext.ExtId)-$($ext.Version)-$($ext.Platform).vsix" $platformUrl)) {
            $failed.Add("$($ext.ExtId)@$($ext.Version) ($($ext.Platform))")
        }
    }
}

# ── Write install.ps1 ──────────────────────────────────────────────────────────
# The generated install.ps1 is self-contained: detects platform at runtime and
# picks platform-specific vsix when available, universal as fallback.

$installContent = @'
# Install VS Code extensions from .vsix files (offline).
# Copy this file AND the vsix\ folder to the target machine, then run:
#   .\install.ps1
param([string]$CodeBinary = "code")

$ErrorActionPreference = "Stop"
$Dir = Join-Path $PSScriptRoot "vsix"

if (-not (Get-Command $CodeBinary -ErrorAction SilentlyContinue)) {
    Write-Error "Error: VS Code CLI '$CodeBinary' not found."
    Write-Error "Use -CodeBinary if using a non-standard install path."
    exit 1
}

function Get-VSCodePlatform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        return if ($arch -eq "Arm64") { "win32-arm64" } else { "win32-x64" }
    } elseif ($IsMacOS) {
        return if ($arch -eq "Arm64") { "darwin-arm64" } else { "darwin-x64" }
    } else {
        return if ($arch -eq "Arm64") { "linux-arm64" } else { "linux-x64" }
    }
}

$platform = Get-VSCodePlatform
Write-Host "Detected platform: $platform"
Write-Host ""

$knownPlatforms = @(
    "linux-x64","linux-arm64","linux-armhf",
    "darwin-arm64","darwin-x64",
    "win32-x64","win32-arm64","win32-ia32",
    "alpine-arm64","alpine-x64"
)

# Build map: base-id-version -> best file
# Priority: 2 = exact platform match, 1 = universal, 0 = other platform
$bestFile     = @{}
$bestPriority = @{}

foreach ($f in Get-ChildItem $Dir -Filter "*.vsix") {
    $stem         = $f.BaseName
    $filePlatform = ""
    $base         = $stem

    foreach ($p in $knownPlatforms) {
        if ($stem.EndsWith("-$p")) {
            $filePlatform = $p
            $base         = $stem.Substring(0, $stem.Length - $p.Length - 1)
            break
        }
    }

    $priority = if ($filePlatform -eq $platform) { 2 }
               elseif ($filePlatform -eq "")     { 1 }
               else                              { 0 }

    $cur = if ($bestPriority.ContainsKey($base)) { $bestPriority[$base] } else { -1 }
    if ($priority -gt $cur) {
        $bestFile[$base]     = $f.Name
        $bestPriority[$base] = $priority
    }
}

$total = $bestFile.Count
Write-Host "Installing $total extensions for platform: $platform"
Write-Host ""

$failed = @()
$n = 0

foreach ($base in $bestFile.Keys) {
    $n++
    $filename = $bestFile[$base]
    Write-Host -NoNewline "  [$n/$total] $filename ... "
    & $CodeBinary --install-extension (Join-Path $Dir $filename) --force 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "ok"
    } else {
        Write-Host "FAILED"
        $failed += $filename
    }
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "Done. Restart VS Code to activate all extensions."
} else {
    Write-Host "$($failed.Count) extension(s) failed to install:"
    foreach ($f in $failed) { Write-Host "  - $f" }
    exit 1
}
'@

$installContent | Set-Content -Path $InstallScript -Encoding UTF8

# ── Write install-from-marketplace.ps1 ────────────────────────────────────────
# Installs each extension directly from the VS Code Marketplace by ID.
# This resets install_source to 'gallery' and re-enables auto-updates.
# Requires internet access on the target machine.

$idList = ($extIds | ForEach-Object {
    $escaped = $_ -replace "'", "''"
    "    '$escaped'"
}) -join ",`n"

$marketplaceContent = @"
# Install VS Code extensions from the Marketplace (online).
# Uninstalls each extension first so VS Code records install_source='gallery',
# which re-enables automatic updates.
#
# IMPORTANT: Close VS Code before running this script.
#   .`\install-from-marketplace.ps1
param([string]`$CodeBinary = "code")

`$ErrorActionPreference = "Stop"

if (-not (Get-Command `$CodeBinary -ErrorAction SilentlyContinue)) {
    Write-Error "Error: VS Code CLI '`$CodeBinary' not found."
    Write-Error "Use -CodeBinary if using a non-standard install path."
    exit 1
}

Write-Host "NOTE: Close VS Code before running this script."
Write-Host "Extensions will be uninstalled then reinstalled from the Marketplace."
Write-Host "Your settings and configuration will not be affected."
Write-Host ""

`$Extensions = @(
$idList
)

`$total = `$Extensions.Count
Write-Host "Reinstalling `$total extensions from Marketplace..."
Write-Host ""

`$failed = @()
`$count = 0

foreach (`$ext in `$Extensions) {
    `$count++
    Write-Host -NoNewline "  [`$count/`$total] `$ext ... "
    & `$CodeBinary --uninstall-extension `$ext 2>&1 | Out-Null
    & `$CodeBinary --install-extension `$ext 2>&1 | Out-Null
    if (`$LASTEXITCODE -eq 0) {
        Write-Host "ok"
    } else {
        Write-Host "FAILED"
        `$failed += `$ext
    }
}

Write-Host ""
if (`$failed.Count -eq 0) {
    Write-Host "Done. Restart VS Code to activate all extensions."
} else {
    Write-Host "`$(`$failed.Count) extension(s) failed to install:"
    foreach (`$f in `$failed) { Write-Host "  - `$f" }
    exit 1
}
"@

$marketplaceContent | Set-Content -Path $MarketplaceScript -Encoding UTF8

# ── Summary ────────────────────────────────────────────────────────────────────

$downloadedCount = (Get-ChildItem $VsixDir -Filter "*.vsix").Count
$totalBytes      = (Get-ChildItem $VsixDir -Filter "*.vsix" | Measure-Object -Property Length -Sum).Sum
$totalSizeGB     = [math]::Round($totalBytes / 1GB, 2)

Write-Host ""
Write-Host "-------------------------------------------------"
Write-Host ("  Downloaded : {0} files ({1} extensions)" -f $downloadedCount, $count)
if ($failed.Count -gt 0) {
    Write-Host ("  Failed     : {0}" -f $failed.Count)
    foreach ($f in $failed) { Write-Host "    - $f" }
}
Write-Host "  Total size : ${totalSizeGB}GB"
Write-Host "  Output     : $OutputDir"
Write-Host "  Offline    : .\install.ps1"
Write-Host "  Marketplace: .\install-from-marketplace.ps1"
Write-Host "-------------------------------------------------"

if ($failed.Count -gt 0) { exit 1 }
