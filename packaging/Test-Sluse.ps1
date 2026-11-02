# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# The acceptance script. D-012 point 3 - separate from the installer, because
# "did it install" and "does it work here" are different questions and a script
# that answered both would let one hide the other.
#
# **What this tests.** That a source with real permissions on it refuses through
# Gate Core: `restricted/` comes back `ACCESS_DENIED`, the one refusal M3
# decided to tell the agent plainly rather than blind (D-008).
#
# CI runs this script on every push against a local NTFS deny ACE, so it is
# exercised rather than read for the first time on the machine that matters.
# **What CI cannot do is be the host.** A local ACL is not a share ACL: over UNC
# the account judged is the cached credential and not the logged-on user, which
# is the distinction that named the wrong principal the first time
# (`docs/development.md`). Run this against `\\FS01\...` and it tests
# something CI cannot reach.
#
# It asks through the console's calls rather than an agent, with
# `sluse-endpoint --query`, which prints each answer as JSON (D-079; it drove
# the console's loopback API until 0.3). An agent tests the tool wording and is
# a scored run's job; this tests the enforcing path, which is Gate Core's.
#
# Records are left where they land and are **not** scored here: the scorers are
# JavaScript and a clean host has no Node (D-012 point 6). Copy the run
# directory back and score it on the development guest.
#
#   .\Test-Sluse.ps1 -SourceRoot \\FS01\share\sluse-fixture

[CmdletBinding()]
param(
    # A tree shaped like the fixture: `in-scope\`, `restricted\`, and something
    # out of scope beside them. `tools\fixture\make-fixture.ps1` generates one.
    [Parameter(Mandatory = $true)]
    [string] $SourceRoot,

    # Where the run workspace goes. Removed and recreated.
    [string] $WorkDir = (Join-Path $env:TEMP 'sluse-acceptance'),

    # Defaults to the bin directory beside this script.
    [string] $BinDir = (Join-Path $PSScriptRoot 'bin'),

    # The request-form path that must refuse. It has to be **below** a
    # configured scope, never a scope root: `scope::compile` canonicalises every
    # scope at start-up, so a deny ACE on the scope itself fails the gate and
    # Gate Core never starts. Under the scope, the same ACE is the refusal M3
    # designed.
    [string] $DeniedPath = 'fixture/restricted/sealed',

    # Leave Gate Core running afterwards.
    [switch] $KeepRunning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sluse = Join-Path $BinDir 'sluse.exe'
$endpoint = Join-Path $BinDir 'sluse-endpoint.exe'
foreach ($exe in $sluse, $endpoint) {
    if (-not (Test-Path $exe)) { throw "missing $exe - pass -BinDir, or run this from the install directory" }
}

$script:pass = 0
$script:fail = 0

function Check {
    param([string] $What, [scriptblock] $Body)
    try {
        $detail = & $Body
        $script:pass++
        Write-Host ("  PASS  {0}" -f $What) -ForegroundColor Green
        if ($detail) { Write-Host ("        {0}" -f $detail) -ForegroundColor DarkGray }
    } catch {
        $script:fail++
        Write-Host ("  FAIL  {0}" -f $What) -ForegroundColor Red
        Write-Host ("        {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
    }
}

# One of the console's answers, from `sluse-endpoint --query`: JSON on stdout,
# exit 0 for an answer and 1 for a refusal, whose error is the JSON then. Any
# other exit is a run that could not ask, and is thrown with what it said
# rather than returned as though Gate Core had refused (2026-09-22: a transport
# failure taken for a refusal cost the first host run its diagnosis).
#
# Start-Process, not `&` with `2>`: the endpoint logs to stderr, and Windows
# PowerShell turns a native command's redirected stderr into errors, which
# `-ErrorAction Stop` throws. **Every path is quoted**: `-ArgumentList` joins
# with spaces and quotes nothing (2026-09-22, `C:\Program Files`).
function Query {
    param([string] $What, [string] $Path)
    $queryArgs = @('--config', "`"$(Join-Path $WorkDir 'sluse.json')`"", '--query', $What)
    if ($Path) { $queryArgs += @('--path', "`"$Path`"") }
    $out = Join-Path $WorkDir 'query.out'
    $err = Join-Path $WorkDir 'query.err'
    $p = Start-Process -FilePath $endpoint -ArgumentList $queryArgs -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 1) {
        throw "sluse-endpoint --query $What exited $($p.ExitCode) - $((Get-Content $err -ErrorAction SilentlyContinue) -join ' ')"
    }
    return @{ ok = ($p.ExitCode -eq 0); body = (Get-Content $out -Raw | ConvertFrom-Json) }
}

Write-Host '--- what is being tested ---'
$versionFile = Join-Path (Split-Path -Parent $BinDir) 'VERSION.txt'
if (Test-Path $versionFile) {
    Get-Content $versionFile | Where-Object { $_ -match '^\s*(version|commit|target|built)' } |
        ForEach-Object { Write-Host "  $_" }
} else {
    Write-Warning 'no VERSION.txt - this is not an installed package, so a result from it names no build'
}
Write-Host "  source    $SourceRoot"
Write-Host ''

if (-not (Test-Path $SourceRoot)) { throw "cannot see $SourceRoot from this machine" }

# ---- lay out a run ----------------------------------------------------------
if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
Write-Host '--- starting ---'
& $sluse start --workspace $WorkDir --fixture $SourceRoot
if ($LASTEXITCODE -ne 0) { throw "sluse start failed with $LASTEXITCODE - the gate log says why" }

try {
    Write-Host ''
    Write-Host '--- checks ---'
    Check 'Sluse Gate is serving' {
        $r = Query state
        if (-not $r.ok) { throw "no state: $($r.body.code)" }
        if ($r.body.gate.status -ne 'serving') { throw "Gate Core is $($r.body.gate.status): $($r.body.gate.detail)" }
        "acting as $($r.body.user.kind):$($r.body.user.name), posture $($r.body.gate.postureId)"
    }

    Check 'the posture snapshot answered, rather than shrugging at everything' {
        # This check used to print the posture id and pass unconditionally - a
        # name that claimed more than the body did. The console's state exposes
        # only the id, so the snapshot itself is read off disk.
        #
        # A machine that is not Windows answers `unknown` to every machine
        # check and still starts, because posture never blocks. That is correct
        # and it is also indistinguishable from a passing run unless somebody
        # counts, which is what this does.
        $snapshot = Join-Path $WorkDir 'audit\gate-posture.jsonl'
        if (-not (Test-Path $snapshot)) { throw "no posture snapshot at $snapshot" }
        $checks = (Get-Content $snapshot | Select-Object -Last 1 | ConvertFrom-Json).checks
        $machine = @($checks | Where-Object { $_.list -eq 'posture' })
        if ($machine.Count -eq 0) { throw 'the snapshot carries no posture checks at all' }

        $answered = @($machine | Where-Object { $_.outcome -in 'pass', 'fail' })
        if ($answered.Count -eq 0) {
            throw "all $($machine.Count) machine checks answered unknown - this is not a Windows host, or the checks are not running"
        }
        $failed = @($machine | Where-Object { $_.outcome -eq 'fail' })
        $summary = "$($answered.Count)/$($machine.Count) answered"
        if ($failed.Count -gt 0) {
            # Reported, not failed. Posture never blocks - that is the design -
            # so a failing machine check is a fact about the machine and worth
            # reading, rather than a reason to call the run bad.
            $summary += '; FAILING: ' + (($failed | ForEach-Object { "$($_.name) - $($_.detail)" }) -join '; ')
        }
        $summary
    }

    Check 'the source is advertised with its scopes in request form' {
        $r = Query sources
        if (-not $r.ok) { throw 'no sources' }
        $s = $r.body.sources[0]
        if (-not $s) { throw 'no source in the config view' }
        foreach ($scope in $s.scopes) {
            if ($scope -match '^[A-Za-z]:\\' -or $scope -match '^\\\\') {
                throw "a host path in the scope list: $scope"
            }
        }
        "$($s.name) ($($s.kind)), scopes: $($s.scopes -join ', ')"
    }

    Check 'the console sees out-of-scope material, marked rather than hidden' {
        $r = Query list 'fixture'
        if (-not $r.ok) { throw "listing refused: $($r.body.code)" }
        $out = @($r.body.entries | Where-Object { -not $_.inScope })
        if ($out.Count -eq 0) { throw 'nothing was marked out of scope; is there anything beside in-scope and restricted?' }
        "greyed: $($out.name -join ', ')"
    }

    Check 'an in-scope directory lists' {
        $r = Query list 'fixture/in-scope'
        if (-not $r.ok) { throw "refused: $($r.body.code)" }
        "$($r.body.entries.Count) entries"
    }

    Check 'a scope whose contents are denied still resolves, so the box starts' {
        # The gate canonicalises every scope. If the deny ACE were on the scope
        # root rather than below it, `sluse start` would have exited 78 and
        # nothing here would have run - which is exactly what happened the first
        # time CI ran this script.
        $r = Query list 'fixture/restricted'
        if (-not $r.ok) { throw "the scope itself refused: $($r.body.code). The deny ACE is on the scope root; move it under the scope" }
        "$($r.body.entries.Count) entries visible in the scope"
    }

    Check 'the denied child is absent from the listing' {
        # Quiet for the browser: an agent walking the tree never learns the
        # name, so it cannot enumerate what it may not have. Loud for the
        # prober: naming it anyway gets ACCESS_DENIED, which the next check
        # asserts. **This is the half that is easy to lose** - it falls out of
        # `canonicalize` failing on a denied handle, and a refactor that made
        # path resolution cheaper would drop it silently.
        $leaf = ($DeniedPath -split '/')[-1]
        $r = Query list 'fixture/restricted'
        if (-not $r.ok) { throw "no listing: $($r.body.code)" }
        if ($r.body.entries.name -contains $leaf) {
            throw "'$leaf' is in the listing. On Windows a denied child should not be. On POSIX it would be, which is why this runs here"
        }
        "'$leaf' exists on disk and is not in the listing"
    }

    # ---- the one that needs a machine with permissions on it ----------------
    Check "$DeniedPath refuses with ACCESS_DENIED, because of an ACL" {
        $r = Query list $DeniedPath
        if ($r.ok) {
            throw "it was served. The deny ACE is not set for the account this machine reaches the source as - Get-SmbSession shows which account that is over a share, and it is the cached credential rather than the logged-on user"
        }
        if ($r.body.code -ne 'ACCESS_DENIED') {
            throw "refused with $($r.body.code), not ACCESS_DENIED. A different code means scope or a missing path, not permissions"
        }
        'the source refused, Gate Core named it, and the console was told plainly'
    }

    Check 'the guest is never told a host path it did not ask for' {
        $r = Query list 'fixture/in-scope'
        if (-not $r.ok) { throw 'no listing' }
        foreach ($e in $r.body.entries) {
            if ($e.name -match '^[A-Za-z]:\\' -or $e.name -match '^\\\\') { throw "a host path in an entry name: $($e.name)" }
        }
        'entry names are names, not paths'
    }
}
finally {
    Write-Host ''
    if ($KeepRunning) {
        Write-Host "left running (stop with: $sluse stop --workspace $WorkDir)"
    } else {
        Write-Host '--- stopping ---'
        & $sluse stop --workspace $WorkDir
    }
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail)
Write-Host ''
Write-Host 'The records are in:'
Write-Host "  $WorkDir\audit\gate.jsonl   the host's side"
Write-Host "  $WorkDir\journal\             the guest's side"
Write-Host ''
Write-Host 'They are not scored here. Copy the run directory to the development'
Write-Host 'guest and run tools/score/{score,join}.js against it - join.js is the'
Write-Host 'only actual claim a run makes, and it needs Node.'

if ($script:fail -gt 0) { exit 1 }
