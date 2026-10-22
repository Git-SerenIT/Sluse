# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# Assemble the release package. D-012 point 3.
#
# **Minimal on purpose.** A zip, a config template, an install script and a
# separate test script. No MSI, no code signing, no build matrix. Chaperone's
# packaging is prior art to lift under D-003 when an installer is actually
# wanted; release engineering is very good at looking like progress and is not
# the product.
#
# This runs on Windows, in CI, because CI is the only route from source to a
# Windows binary (D-012 point 2): the development guest is Linux and the host
# has no toolchain.
#
# Usage:
#   .\packaging\build-package.ps1                     # build and zip
#   .\packaging\build-package.ps1 -SkipBuild          # zip what is already built

[CmdletBinding()]
param(
    # Where the package is assembled and the zip written.
    [string] $OutDir = 'dist',

    # Reuse an existing release build rather than running cargo.
    [switch] $SkipBuild,

    # CI: build and stage, without the Linux bundle and without the zip. The
    # install job adds the bundle from the Linux job and zips (ci.yml).
    [switch] $StageOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    # ---- what this package claims to be -----------------------------------
    #
    # Version comes from the workspace manifest, never typed here: two places
    # holding one version number is how a package ends up lying about itself.
    $manifest = Get-Content 'Cargo.toml' -Raw
    if ($manifest -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw 'no version in the workspace Cargo.toml'
    }
    $version = $Matches[1]
    # The other three places that state it must agree (D-068): the shell's
    # own workspace and the two UIs' package files. A release takes its tag
    # from this version, so a disagreement is a package lying about itself.
    $others = @{
        'ui\shell\src-tauri\Cargo.toml' = '(?m)^version\s*=\s*"([^"]+)"'
        'ui\shell\package.json'          = '"version":\s*"([^"]+)"'
        'ui\console\package.json'        = '"version":\s*"([^"]+)"'
    }
    foreach ($f in $others.Keys) {
        if ((Get-Content $f -Raw) -notmatch $others[$f] -or $Matches[1] -ne $version) {
            throw "$f does not say version $version; every version field says the workspace's"
        }
    }

    # The commit is what makes a package traceable back to a tree. A build from
    # a dirty tree says so, because "it works" about an unrecorded state is not
    # a claim anybody can check later.
    $commit = (git rev-parse --short HEAD).Trim()
    $dirty = if (git status --porcelain) { '-dirty' } else { '' }
    $stamp = "$version+$commit$dirty"

    $target = 'x86_64-pc-windows-msvc'
    $name = "sluse-$version-$target"
    $stage = Join-Path $OutDir $name

    Write-Host "package  $stamp"
    Write-Host "target   $target"

    # ---- build -------------------------------------------------------------
    if (-not $SkipBuild) {
        # `--locked`: a package built from a resolved-on-the-fly graph is not the
        # graph the tests ran against.
        cargo build --workspace --release --locked
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with $LASTEXITCODE" }

        # The console is TypeScript and ships built. `npm ci`, not `install`:
        # the lock file is what CI and a developer agree on.
        npm --prefix ui/console ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed with $LASTEXITCODE" }
        npm --prefix ui/console run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed with $LASTEXITCODE" }

        # The host shell (D-025): its own Cargo workspace and lock file, built
        # by Tauri's CLI, which runs the frontend's copy step first. No bundle:
        # the MSI packages it (slice 5).
        npm --prefix ui/shell ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci (shell) failed with $LASTEXITCODE" }
        Push-Location ui/shell
        try {
            npx tauri build --no-bundle -- --locked
            if ($LASTEXITCODE -ne 0) { throw "tauri build failed with $LASTEXITCODE" }
        } finally { Pop-Location }
    }

    # ---- assemble ----------------------------------------------------------
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    $null = New-Item -ItemType Directory -Path (Join-Path $stage 'bin') -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stage 'config') -Force
    $null = New-Item -ItemType Directory -Path (Join-Path $stage 'ui\console') -Force

    # Three binaries, and the names are the ones the docs use. `sluse.exe` is
    # the lifecycle crate's binary; the crate name and the command differ and
    # that is deliberate (docs/sluse_prototype.md).
    foreach ($exe in 'sluse.exe', 'sluse-broker.exe', 'sluse-endpoint.exe') {
        $src = Join-Path 'target\release' $exe
        if (-not (Test-Path $src)) { throw "missing $src - was the release build run?" }
        Copy-Item $src (Join-Path $stage 'bin') -Force
    }

    $shellExe = 'ui\shell\src-tauri\target\release\sluse-shell.exe'
    if (-not (Test-Path $shellExe)) { throw "missing $shellExe - was the shell built?" }
    Copy-Item $shellExe (Join-Path $stage 'bin') -Force

    # The box's bundle, built on Linux (packaging/box/build-bundle.sh; in CI,
    # the guest job's artifact). The service's base build carries it onto the
    # seed disk (slice 3). A package without it cannot make a box.
    if (-not $StageOnly) {
        $bundle = Join-Path $OutDir 'sluse-box-linux.tar.gz'
        if (-not (Test-Path $bundle)) { throw "missing $bundle - build it on Linux with packaging/box/build-bundle.sh" }
        $null = New-Item -ItemType Directory -Path (Join-Path $stage 'box') -Force
        Copy-Item $bundle (Join-Path $stage 'box') -Force
    }

    # The console: the page, its stylesheet, the shared look and the compiled modules. Not the
    # TypeScript, not node_modules - what ships is what a browser loads.
    Copy-Item 'ui\console\index.html' (Join-Path $stage 'ui\console') -Force
    Copy-Item 'ui\console\look'       (Join-Path $stage 'ui\console\look') -Recurse -Force
    Copy-Item 'ui\console\style.css'  (Join-Path $stage 'ui\console') -Force
    if (-not (Test-Path 'ui\console\dist\main.js')) {
        throw 'ui/console/dist/main.js is missing - the console was not built'
    }
    Copy-Item 'ui\console\dist' (Join-Path $stage 'ui\console\dist') -Recurse -Force

    Copy-Item 'config\local.example.json'        (Join-Path $stage 'config') -Force
    Copy-Item 'config\local.example.device.json' (Join-Path $stage 'config') -Force
    Copy-Item 'config\schema.json'               (Join-Path $stage 'config') -Force
    Copy-Item 'config\device.schema.json'        (Join-Path $stage 'config') -Force
    # The egress bundles setup offers, and what posture compares with (D-038).
    Copy-Item 'config\egress-catalog.json'       (Join-Path $stage 'config') -Force

    # Nothing runs from Sluse Artifacts (D-039 slice 8): the App Control
    # policy, as XML and as the binary .cip Intune's custom OMA-URI takes,
    # for the admin to deploy. ConvertFrom-CIPolicy also checks the XML.
    $intune = Join-Path $stage 'intune'
    $null = New-Item -ItemType Directory -Path $intune -Force
    $policy = 'packaging\intune\sluse-artifacts-deny.xml'
    Copy-Item $policy $intune -Force
    $id = ([xml](Get-Content $policy)).SiPolicy.PolicyID
    # Windows PowerShell's own ConfigCI module, whatever shell runs this.
    $xmlPath = (Resolve-Path $policy).Path
    $cipPath = Join-Path (Resolve-Path $intune).Path "$id.cip"
    powershell.exe -NoProfile -Command "ConvertFrom-CIPolicy -XmlFilePath '$xmlPath' -BinaryFilePath '$cipPath' | Out-Null"
    if ($LASTEXITCODE -ne 0) { throw "ConvertFrom-CIPolicy exited $LASTEXITCODE" }
    if (-not (Test-Path (Join-Path $intune "$id.cip"))) { throw "ConvertFrom-CIPolicy made no $id.cip" }

    Copy-Item 'packaging\Install-Sluse.ps1' $stage -Force
    Copy-Item 'packaging\Test-Sluse.ps1'    $stage -Force
    Copy-Item 'packaging\README.md'         $stage -Force

    # ---- what it is, recorded inside it ------------------------------------
    #
    # A package that cannot say which tree it came from is a package nobody can
    # check a result against later. This file is the first thing a test script
    # reads and the first thing to quote in a run record.
    @"
version   $version
commit    $commit$dirty
target    $target
built     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
builder   $env:COMPUTERNAME
rustc     $((rustc --version).Trim())

This is a prototype build. 0.0.x, and it stays there until something has been
run against a real source by someone other than its author.
"@ | Set-Content (Join-Path $stage 'VERSION.txt') -Encoding utf8

    # ---- zip ---------------------------------------------------------------
    if ($StageOnly) {
        Write-Host "staged   $stage (no box bundle, no zip: -StageOnly)"
        return
    }
    $zip = Join-Path $OutDir "$name.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal

    $size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
    Write-Host ''
    Write-Host "  $zip  ($size MB)"
    Get-ChildItem $stage -Recurse -File | ForEach-Object {
        Write-Host ("    {0}" -f (Resolve-Path $_.FullName -Relative))
    }
}
finally {
    Pop-Location
}
