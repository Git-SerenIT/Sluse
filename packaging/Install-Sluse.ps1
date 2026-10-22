# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# Install Sluse from an unpacked release. D-012.
#
# **What this does not do, and the list is the point.** No registry keys, no
# firewall rules, no certificate store, no PATH surgery beyond one optional
# opt-in, and **no Windows service**: the MSI (slice 5, D-027) installs and
# starts the service. This is the LOCAL copy-and-check install.
#
# What it does: copy files to a directory, verify the binaries run there, and
# tell you the two commands that come next. Installability is the claim being
# tested (`prototype/README.md`), and this is the smallest thing that can be
# said to test it.
#
# Its `-Service` mode, which registered the service and never started it while
# saying it had, was removed on 2026-10-15 (review R-23): the MSI owns the
# service, and two ways to install it is one too many.
#
# Run from inside the unpacked package:
#   .\Install-Sluse.ps1
#   .\Install-Sluse.ps1 -InstallDir 'D:\Sluse' -AddToPath

[CmdletBinding()]
param(
    # Where it goes. Per-machine by default, because the broker is a host
    # service in the product even though it is a child process in the prototype.
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'Sluse'),

    # Overwrite an existing installation.
    [switch] $Force,

    # Add the bin directory to the user's PATH. Opt-in: an installer that edits
    # PATH without being asked is an installer people stop trusting.
    [switch] $AddToPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$package = $PSScriptRoot

# ---- what is being installed -----------------------------------------------
$versionFile = Join-Path $package 'VERSION.txt'
if (-not (Test-Path $versionFile)) {
    throw "no VERSION.txt beside this script. Run it from inside an unpacked package, not from a source tree."
}
Write-Host '--- installing ---'
Get-Content $versionFile | Where-Object { $_ -match '\S' } | ForEach-Object { Write-Host "  $_" }

# ---- refuse to guess -------------------------------------------------------
if ((Test-Path $InstallDir) -and -not $Force) {
    $existing = Join-Path $InstallDir 'VERSION.txt'
    if (Test-Path $existing) {
        Write-Host ''
        Write-Host 'Already installed there:'
        Get-Content $existing | Select-Object -First 2 | ForEach-Object { Write-Host "  $_" }
    }
    throw "$InstallDir exists. Pass -Force to replace it."
}

# Writing under Program Files needs elevation, and finding that out from an
# access-denied halfway through a copy is worse than being told now.
$elevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated -and $InstallDir.StartsWith($env:ProgramFiles, 'OrdinalIgnoreCase')) {
    throw "installing to $InstallDir needs an elevated prompt. Either elevate, or pass -InstallDir somewhere writable."
}

# ---- the MSI's service runs from its own directory -------------------------
# Replacing its files would replace the service's under it. Refused, not done.
$svc = Get-CimInstance Win32_Service -Filter "Name='Sluse'" -ErrorAction SilentlyContinue
if ($svc -and $svc.PathName -and $svc.PathName.IndexOf($InstallDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    throw "the Sluse service (the MSI) runs from $InstallDir. Pass -InstallDir somewhere else, or remove the MSI first."
}

# ---- copy ------------------------------------------------------------------
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $InstallDir -Force

foreach ($item in 'bin', 'box', 'ui', 'config', 'VERSION.txt', 'README.md', 'Test-Sluse.ps1') {
    $src = Join-Path $package $item
    if (Test-Path $src) { Copy-Item $src $InstallDir -Recurse -Force }
}

$bin = Join-Path $InstallDir 'bin'

# ---- verify it actually runs there -----------------------------------------
#
# A copy that finished is not an install that works: the usual failure is a
# missing runtime, and `+crt-static` in `.cargo/config.toml` exists so this
# cannot be the VC++ redistributable. If it is something else, better to learn
# it here than from an agent run.
Write-Host ''
Write-Host '--- verifying ---'
foreach ($exe in 'sluse.exe', 'sluse-broker.exe', 'sluse-endpoint.exe') {
    $path = Join-Path $bin $exe
    if (-not (Test-Path $path)) { throw "missing $exe" }
    $out = & $path --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$exe would not run here: $out" }
    Write-Host ("  {0,-20} {1}" -f $exe, ($out -join ' ').Trim())
}

$consolePage = Join-Path $InstallDir 'ui\console\index.html'
if (Test-Path $consolePage) {
    Write-Host ("  {0,-20} present" -f 'console')
} else {
    Write-Warning 'the console is not in this package; --console will serve its API and no views'
}

# ---- PATH, if asked --------------------------------------------------------
if ($AddToPath) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($current -split ';' -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', "$current;$bin", 'User')
        Write-Host "  PATH                 added $bin (new shells only)"
    } else {
        Write-Host "  PATH                 already has $bin"
    }
}

# ---- what comes next -------------------------------------------------------
Write-Host ''
Write-Host "Installed to $InstallDir"
Write-Host ''
Write-Host 'No service: the MSI installs that. A LOCAL run is laid out by'
Write-Host '`sluse start`, which writes its own config, development certificates,'
Write-Host 'launcher and task into a workspace you name:'
Write-Host ''
Write-Host "  $bin\sluse.exe start --workspace <run dir> --fixture <source root>"
Write-Host ''
Write-Host 'To check this machine before running anything:'
Write-Host ''
Write-Host "  $bin\sluse.exe check --config <a config file>"
Write-Host ''
Write-Host 'To run the acceptance script against a source you have permissions set on:'
Write-Host ''
Write-Host "  $InstallDir\Test-Sluse.ps1 -SourceRoot <path or UNC>"
