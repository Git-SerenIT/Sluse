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
# It drives the console's loopback API rather than an agent. An agent tests the
# tool wording and is a scored run's job; this tests the enforcing path, which
# is Gate Core's, and which answers over HTTP where a script can check it.
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

    # Leave Gate Core and console running afterwards, to look at the console.
    [switch] $KeepRunning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sluse = Join-Path $BinDir 'sluse.exe'
$endpoint = Join-Path $BinDir 'sluse-endpoint.exe'
foreach ($exe in $sluse, $endpoint) {
    if (-not (Test-Path $exe)) { throw "missing $exe - pass -BinDir, or run this from the install directory" }
}
$ui = Join-Path (Split-Path -Parent $BinDir) 'ui\console'
$console = 'http://127.0.0.1:7582'

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

# `Invoke-RestMethod` throws on a non-2xx, and the refusals are the interesting
# answers here - so the body is caught and returned rather than thrown away.
#
# **A refusal is an answer; a transport failure is not**, and conflating them
# cost the first host run its diagnosis (2026-09-22). Under `Set-StrictMode
# -Version Latest` a missing property is fatal, and neither `ErrorDetails` nor
# `Exception.Response` exists when nothing answered at all - so the real error
# was replaced by "the property 'Message' cannot be found on this object" and
# every check reported it. Both dereferences are guarded now, and a failure
# with no HTTP status is rethrown with what the transport actually said rather
# than returned as though the console had refused.
function Api {
    param([string] $Path)
    try {
        return @{ ok = $true; body = (Invoke-RestMethod -Uri "$console$Path" -TimeoutSec 20) }
    } catch {
        $status = $null
        $response = $_.Exception.PSObject.Properties['Response']
        if ($response -and $response.Value) { $status = [int] $response.Value.StatusCode }
        if ($null -eq $status) { throw "no answer from $console$Path - $($_.Exception.Message)" }
        $body = $null
        if ($null -ne $_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $body = $_.ErrorDetails.Message | ConvertFrom-Json } catch { $body = $_.ErrorDetails.Message }
        }
        return @{ ok = $false; status = $status; body = $body }
    }
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

# A hidden window throws away everything the console says about why it would
# not start, and three seconds was a guess. Its output goes to files beside the
# run and the script waits until it answers, the way `sluse start` waits for the
# Gate.
$consoleOut = Join-Path $WorkDir 'console.log'
$consoleErr = Join-Path $WorkDir 'console.err'
# **Every path is quoted.** `Start-Process -ArgumentList` joins an array with
# spaces and quotes nothing, so `C:\Program Files\Sluse\ui\console` arrives as
# two arguments and the endpoint exits 2 on an unexpected one. Found on the host
# on 2026-09-22, against the default install directory of this package's own
# installer; CI had only ever installed to a path with no space in it.
$consoleProc = Start-Process -FilePath $endpoint `
    -ArgumentList '--config', "`"$(Join-Path $WorkDir 'sluse.json')`"", '--console', '--ui', "`"$ui`"" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $consoleOut -RedirectStandardError $consoleErr

try {
    $ready = $false
    foreach ($attempt in 1..20) {
        if ($consoleProc.HasExited) { break }
        try {
            Invoke-RestMethod -Uri "$console/api/state" -TimeoutSec 2 | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        $said = @(Get-Content $consoleOut, $consoleErr -ErrorAction SilentlyContinue) -join "`n"
        $exited = if ($consoleProc.HasExited) { "it exited with $($consoleProc.ExitCode)" } else { 'it is still running but not answering' }
        throw "the console never answered on $console after 20 tries - $exited. It said:`n$said`nCheck: is 7582 already held (Get-NetTCPConnection -LocalPort 7582), and does $ui exist"
    }

    Write-Host ''
    Write-Host '--- checks ---'
    Check 'Sluse Gate is serving' {
        $r = Api '/api/state'
        if (-not $r.ok) { throw "the console did not answer" }
        if ($r.body.gate.status -ne 'serving') { throw "Gate Core is $($r.body.gate.status): $($r.body.gate.detail)" }
        "acting as $($r.body.user.kind):$($r.body.user.name), posture $($r.body.gate.postureId)"
    }

    Check 'the posture snapshot answered, rather than shrugging at everything' {
        # This check used to print the posture id and pass unconditionally - a
        # name that claimed more than the body did. The console's API exposes
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
        $r = Api '/api/sources'
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
        $r = Api '/api/list?path=fixture'
        if (-not $r.ok) { throw "listing refused: $($r.body.code)" }
        $out = @($r.body.entries | Where-Object { -not $_.inScope })
        if ($out.Count -eq 0) { throw 'nothing was marked out of scope; is there anything beside in-scope and restricted?' }
        "greyed: $($out.name -join ', ')"
    }

    Check 'an in-scope directory lists' {
        $r = Api '/api/list?path=fixture/in-scope'
        if (-not $r.ok) { throw "refused: $($r.body.code)" }
        "$($r.body.entries.Count) entries"
    }

    Check 'a scope whose contents are denied still resolves, so the box starts' {
        # The gate canonicalises every scope. If the deny ACE were on the scope
        # root rather than below it, `sluse start` would have exited 78 and
        # nothing here would have run - which is exactly what happened the first
        # time CI ran this script.
        $r = Api '/api/list?path=fixture/restricted'
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
        $r = Api '/api/list?path=fixture/restricted'
        if (-not $r.ok) { throw "no listing: $($r.body.code)" }
        if ($r.body.entries.name -contains $leaf) {
            throw "'$leaf' is in the listing. On Windows a denied child should not be. On POSIX it would be, which is why this runs here"
        }
        "'$leaf' exists on disk and is not in the listing"
    }

    # ---- the one that needs a machine with permissions on it ----------------
    Check "$DeniedPath refuses with ACCESS_DENIED, because of an ACL" {
        $r = Api "/api/list?path=$([uri]::EscapeDataString($DeniedPath))"
        if ($r.ok) {
            throw "it was served. The deny ACE is not set for the account this machine reaches the source as - Get-SmbSession shows which account that is over a share, and it is the cached credential rather than the logged-on user"
        }
        if ($r.body.code -ne 'ACCESS_DENIED') {
            throw "refused with $($r.body.code), not ACCESS_DENIED. A different code means scope or a missing path, not permissions"
        }
        'the source refused, Gate Core named it, and the console was told plainly'
    }

    Check 'the guest is never told a host path it did not ask for' {
        $r = Api '/api/list?path=fixture/in-scope'
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
        Write-Host "left running: $console  (stop with: Stop-Process -Id $($consoleProc.Id); $sluse stop --workspace $WorkDir)"
    } else {
        Write-Host '--- stopping ---'
        if ($consoleProc -and -not $consoleProc.HasExited) { Stop-Process -Id $consoleProc.Id -Force }
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
