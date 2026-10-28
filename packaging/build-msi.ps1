# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# The staged package and the box's bundle, assembled, built into dist\Sluse.msi.
# CI's `sign` job runs it between signing the binaries and signing the MSI, and
# `install` runs it when `sign` was skipped (D-071 point 8). Run from the
# repository root, with the staged package and sluse-box-linux.tar.gz in dist\.
$ErrorActionPreference = 'Stop'

$pkg = @(Get-ChildItem dist -Directory | Where-Object Name -like 'sluse-*-x86_64-pc-windows-msvc')
if ($pkg.Count -ne 1) { Get-ChildItem dist -Recurse -Depth 1; throw "expected one staged package in dist, found $($pkg.Count)" }
$pkg = $pkg[0].FullName
New-Item -ItemType Directory -Force (Join-Path $pkg 'box') | Out-Null
Copy-Item dist\sluse-box-linux.tar.gz (Join-Path $pkg 'box')

dotnet tool install --global wix --version 5.0.2
if ($LASTEXITCODE -ne 0) { throw "dotnet tool install wix failed with $LASTEXITCODE" }
wix extension add -g WixToolset.UI.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "wix extension add failed with $LASTEXITCODE" }
$version = (Get-Content "$pkg\VERSION.txt" | Select-String '^version').Line -replace '^version\s+', ''
wix build packaging\msi\Sluse.wxs -ext WixToolset.UI.wixext -arch x64 -d "Stage=$pkg" -d "Version=$version" -o dist\Sluse.msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed with $LASTEXITCODE" }
