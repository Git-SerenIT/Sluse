# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# Hyper-V, for the lifecycle service (D-027 design point 1). S-8's proven
# spike scripts, promoted. Not run by hand: the service embeds this file and
# runs it as SYSTEM in Windows PowerShell 5.1, like this:
#
#   $env:SLUSE_BOX_ARGS = '{"verb":"state","vm":"sluse-box"}'
#   powershell.exe -NoProfile -NonInteractive -Command `
#       "& ([scriptblock]::Create($env:SLUSE_BOX_PS))"
#
# The script travels in an environment variable, not as a file, so a machine
# policy of AllSigned does not refuse it: execution policy applies to script
# files, not to a scriptblock. The arguments travel as JSON, so nothing is
# ever spliced into a command line.
#
# Output: one JSON line on stdout. A failure is a terminating error, which
# PowerShell prints to stderr and exits 1 on.

$ErrorActionPreference = 'Stop'
# Danish, or any, error text arrives intact rather than in the OEM code page.
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$a = $env:SLUSE_BOX_ARGS | ConvertFrom-Json
# The disk verbs name no VM; every VM name is checked before it reaches a
# cmdlet or the WMI filter below.
if ($null -ne $a.vm -and $a.vm -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "not a VM name: $($a.vm)" }
$ns = 'root\virtualization\v2'

function Out-Json($o) { $o | ConvertTo-Json -Compress -Depth 4 }

# A box's processors (D-045 point 7): 4 where the host has 8 or more logical
# processors, else 2.
function Box-Cpus { if ((Get-VMHost).LogicalProcessorCount -ge 8) { 4 } else { 2 } }

function Wait-WmiJob($r, $what) {
    if ($r.ReturnValue -eq 0) { return }
    if ($r.ReturnValue -ne 4096) { throw "$what returned $($r.ReturnValue)" }
    $job = [wmi]$r.Job
    while ($job.JobState -in 3, 4) { Start-Sleep -Milliseconds 200; $job = [wmi]$r.Job }
    if ($job.JobState -ne 7) { throw "$what ended in job state $($job.JobState): $($job.ErrorDescription)" }
}

function Kvp-Item($name, $data) {
    $i = ([wmiclass]"\\.\$($ns):Msvm_KvpExchangeDataItem").CreateInstance()
    $i.Name = $name
    $i.Data = $data
    $i.Source = 0   # host to guest: the box reads /var/lib/hyperv/.kvp_pool_0
    $i.PSBase.GetText([System.Management.TextFormat]::CimDtd20)
}

# D-023, D-039 slice 7: Sluse's records in a log of their own, "Sluse",
# whose descriptor lets only SYSTEM write (Sluse Gate is
# SYSTEM). An older device's source in the Application log, which any
# process may write to, moves here; its old records stay where they are.
# Not proof against an administrator, who can change the descriptor.
# The SDDL equals sluse_gate_core::audit::AUDIT_SDDL (a test says so).
function Set-SluseLog {
    $sddl = 'O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x1;;;BA)(A;;0x1;;;S-1-5-32-573)'
    if ([Diagnostics.EventLog]::SourceExists('Sluse') -and [Diagnostics.EventLog]::LogNameFromSourceName('Sluse', '.') -ne 'Sluse') {
        Remove-EventLog -Source 'Sluse'
    }
    if (-not [Diagnostics.EventLog]::SourceExists('Sluse')) { New-EventLog -LogName 'Sluse' -Source 'Sluse' }
    # ponytail: 64 MB, overwritten as needed; a SIEM agent is expected to
    # collect it. A retention setting when a customer asks for one.
    Limit-EventLog -LogName 'Sluse' -MaximumSize 64MB -OverflowAction OverwriteAsNeeded
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Sluse' -Name CustomSD -Value $sddl
}

# IT-facing names (Q66): the firewall rule says "Sluse Gate" (D-071).
$FirewallRule = 'Sluse boxes: Sluse Gate (host-only)'

# What Hyper-V Manager says about a box (Q67).
function Box-Notes([string] $who) {
    "Sluse box for $who. Sluse makes, resets and deletes it; change it only through Sluse."
}

switch ($a.verb) {
    'state' {
        $vm = Get-VM -Name $a.vm -ErrorAction SilentlyContinue
        if (-not $vm) { Out-Json @{ state = 'none' } }
        elseif ($vm.State -eq 'Running') { Out-Json @{ state = 'running' } }
        else { Out-Json @{ state = 'off'; hyperv = "$($vm.State)" } }
    }
    'start' {
        $vm = Get-VM -Name $a.vm
        # COM1 to a named pipe the service reads into the box's console.log
        # (D-030). Set while the VM is off, which is also how a box made
        # before D-030 gets it. The service reads; nothing writes.
        if ($vm.State -eq 'Off') { Set-VMComPort -VMName $a.vm -Number 1 -Path $a.pipe }
        if ($vm.State -ne 'Running') { Start-VM -VM $vm }
        Out-Json @{ state = 'running' }
    }
    'stop' {
        $vm = Get-VM -Name $a.vm
        # A clean shutdown through the Shutdown integration service; -Force
        # only skips the prompt. The disks are kept (D-026 point 1). Waited
        # for $a.seconds, then turned off: a box that does not shut down
        # (the enrolment deadlock, L1 2026-09-30) is not waited on for ever.
        $turnedOff = $false
        if ($vm.State -ne 'Off') {
            $job = Stop-VM -Name $a.vm -Force -AsJob
            if (-not (Wait-Job $job -Timeout ([int]$a.seconds))) {
                Stop-VM -Name $a.vm -TurnOff -Force
                $turnedOff = $true
            }
            Remove-Job $job -Force
        }
        Out-Json @{ state = 'off'; turnedOff = $turnedOff }
    }
    'kvp' {
        # Modify a key that exists, add one that does not: AddKvpItems refuses
        # a key that exists, and ModifyKvpItems one that does not. Not remove
        # then add, which rewrote the box's pool twice, the first time without
        # the key, and a theme switch was lost behind it (L1, 2026-10-21).
        # Several items in order, in one call: the theme and the bootstrap at
        # an open (Q70), so the open pays for one PowerShell, not two.
        $svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemManagementService
        $vm = Get-WmiObject -Namespace $ns -Class Msvm_ComputerSystem -Filter "ElementName='$($a.vm)'"
        if (-not $vm) { throw "no VM named $($a.vm)" }
        foreach ($i in @($a.items)) {
            try { Wait-WmiJob ($svc.ModifyKvpItems($vm, @(Kvp-Item $i.key $i.value))) 'ModifyKvpItems' }
            catch { Wait-WmiJob ($svc.AddKvpItems($vm, @(Kvp-Item $i.key $i.value))) 'AddKvpItems' }
        }
        Out-Json @{ sent = @($a.items | ForEach-Object { $_.key }) }
    }
    # ---- slice 3: the base, built once per device --------------------------
    'base-from-vhd' {
        # Our fixed VHD to Hyper-V's own dynamic VHDX, grown to the box's
        # disk; cloud-init grows the root partition into it. Convert-VHD's
        # output is not sparse (S-8 step 4). A half-built base from an earlier
        # try goes first. The fixed VHD stays until a build succeeds, so a
        # retry needs no download (D-063).
        if (Test-Path $a.base) {
            Set-ItemProperty $a.base -Name IsReadOnly -Value $false
            Remove-Item $a.base -Force
        }
        Convert-VHD -Path $a.vhd -DestinationPath $a.base -VHDType Dynamic
        Resize-VHD -Path $a.base -SizeBytes ([int64]$a.gb * 1GB)
        Out-Json @{ base = $a.base }
    }
    'seed' {
        # The NoCloud seed: a small FAT disk labelled CIDATA, attached to the
        # build VM only, before anything is in the box (S-8 step 3).
        if (Test-Path $a.seed) { Remove-Item $a.seed -Force }
        New-VHD -Path $a.seed -SizeBytes 256MB -Dynamic | Out-Null
        $d = Mount-VHD -Path $a.seed -Passthru | Get-Disk
        try {
            Initialize-Disk -Number $d.Number -PartitionStyle MBR
            $part = New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter
            $part = Get-Partition -DiskNumber $d.Number -PartitionNumber $part.PartitionNumber
            Format-Volume -Partition $part -FileSystem FAT -NewFileSystemLabel CIDATA -Confirm:$false | Out-Null
            $root = "$($part.DriveLetter):\"
            # YAML for cloud-init: LF, no BOM, whatever the console does.
            foreach ($f in $a.files.PSObject.Properties) {
                [IO.File]::WriteAllText((Join-Path $root $f.Name), ($f.Value -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
            }
            foreach ($c in @($a.copy)) { if ($c) { Copy-Item $c $root } }
        } finally { Dismount-VHD -Path $a.seed }
        Out-Json @{ seed = $a.seed }
    }
    'build-vm' {
        # The base itself is the build VM's disk: what cloud-init installs is
        # the base. No box is made from it until it is sealed.
        if (Get-VM -Name $a.vm -ErrorAction SilentlyContinue) {
            Stop-VM -Name $a.vm -TurnOff -Force -ErrorAction SilentlyContinue
            Remove-VM -Name $a.vm -Force
        }
        New-VM -Name $a.vm -Generation 2 -MemoryStartupBytes ([int64]$a.memoryGB * 1GB) -VHDPath $a.base -SwitchName $a.switch | Out-Null
        Set-VM -Name $a.vm -ProcessorCount (Box-Cpus) -StaticMemory -CheckpointType Disabled -AutomaticCheckpointsEnabled $false
        Set-VMFirmware -VMName $a.vm -SecureBootTemplate MicrosoftUEFICertificateAuthority
        Add-VMHardDiskDrive -VMName $a.vm -Path $a.seed
        Disable-VMIntegrationService -VMName $a.vm -Name 'Guest Service Interface'
        # COM1 to the pipe the service records the build's console from: its
        # last line says whether the build is whole (D-063).
        Set-VMComPort -VMName $a.vm -Number 1 -Path $a.pipe
        Start-VM -Name $a.vm
        Out-Json @{ state = 'running' }
    }
    'finish-build' {
        # The build VM goes. A whole build's disk stays, read-only, as the
        # base, and the fixed VHD it came from goes; a build that did not
        # finish leaves no disk, and the fixed VHD stays for the next try
        # (D-063).
        Remove-VM -Name $a.vm -Force
        Remove-Item $a.seed -Force -ErrorAction SilentlyContinue
        if ($a.keep) {
            Set-ItemProperty $a.base -Name IsReadOnly -Value $true
            Remove-Item $a.vhd -Force -ErrorAction SilentlyContinue
        } else {
            Remove-Item $a.base -Force -ErrorAction SilentlyContinue
        }
        Out-Json @{ base = $a.base; kept = [bool]$a.keep }
    }
    'create-box' {
        # A user's box: a system disk on the base, and the user's own home
        # disk, made blank here and formatted by the box on its first boot
        # (sluse-home.service). Both are kept on close (D-026 point 1).
        New-VHD -Path $a.system -ParentPath $a.base -Differencing | Out-Null
        if (-not (Test-Path $a.home)) { New-VHD -Path $a.home -SizeBytes ([int64]$a.homeGB * 1GB) -Dynamic | Out-Null }
        New-VM -Name $a.vm -Generation 2 -MemoryStartupBytes ([int64]$a.memoryGB * 1GB) -VHDPath $a.system -SwitchName $a.switch | Out-Null
        Set-VM -Name $a.vm -ProcessorCount (Box-Cpus) -StaticMemory -CheckpointType Disabled -AutomaticCheckpointsEnabled $false `
            -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
        Set-VMFirmware -VMName $a.vm -SecureBootTemplate MicrosoftUEFICertificateAuthority
        Add-VMHardDiskDrive -VMName $a.vm -Path $a.home
        Disable-VMIntegrationService -VMName $a.vm -Name 'Guest Service Interface'
        # Hyper-V Manager says whose box this is (Q67): the Windows account
        # now, the work account once a sign-in names it ('box-notes').
        $who = (New-Object System.Security.Principal.SecurityIdentifier $a.sid).Translate([System.Security.Principal.NTAccount]).Value
        Set-VM -Name $a.vm -Notes (Box-Notes $who)
        Out-Json @{ vm = $a.vm }
    }
    'box-notes' {
        Set-VM -Name $a.vm -Notes (Box-Notes $a.who)
        Out-Json @{ vm = $a.vm }
    }
    'size-box' {
        # The config's box size (D-038 point 7), before each start: memory as
        # set, the processors for this host (D-045 point 7), the home disk grown and never shrunk. Only on a box that is
        # off; a running one keeps what it has until it is closed.
        $vm = Get-VM -Name $a.vm
        $changed = @()
        if ($vm.State -eq 'Off') {
            $want = [int64]$a.memoryGB * 1GB
            if ($vm.MemoryStartup -ne $want) {
                Set-VMMemory -VMName $a.vm -StartupBytes $want
                $changed += "memory $([int64]($vm.MemoryStartup / 1GB)) GB -> $($a.memoryGB) GB"
            }
            $cpus = Box-Cpus
            if ($vm.ProcessorCount -ne $cpus) {
                Set-VMProcessor -VMName $a.vm -Count $cpus
                $changed += "processors $($vm.ProcessorCount) -> $cpus"
            }
            $home_ = [int64]$a.homeGB * 1GB
            $size = (Get-VHD -Path $a.home).Size
            if ($size -lt $home_) {
                Resize-VHD -Path $a.home -SizeBytes $home_
                $changed += "home disk $([int64]($size / 1GB)) GB -> $($a.homeGB) GB"
            }
        }
        $hostGB = [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
        Out-Json @{ state = "$($vm.State)"; changed = $changed; hostGB = $hostGB }
    }
    # ---- slice 4: the user's controls ---------------------------------------
    'remove-box' {
        # Reset: the VM and its system disk. Wipe: the home disk too. Neither
        # touches the host's records (D-026 point 2).
        $vm = Get-VM -Name $a.vm -ErrorAction SilentlyContinue
        if ($vm) {
            if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force -ErrorAction SilentlyContinue }
            if ((Get-VM -Name $a.vm).State -ne 'Off') { Stop-VM -Name $a.vm -TurnOff -Force }
            Remove-VM -Name $a.vm -Force
        }
        foreach ($p in @($a.system, $a.home)) { if ($p -and (Test-Path $p)) { Remove-Item $p -Force } }
        Out-Json @{ removed = $a.vm }
    }
    'remove-file' {
        # A base no box stands on any more: read-only, so the flag goes first.
        if (Test-Path $a.path) {
            Set-ItemProperty $a.path -Name IsReadOnly -Value $false
            Remove-Item $a.path -Force
        }
        Out-Json @{ removed = $a.path }
    }
    # ---- slice 5: the device ------------------------------------------------
    'device-init' {
        # The host's side of the segment, idempotent: run at every service
        # start. Hyper-V itself is the MSI's to enable, with its reboot
        # (D-024 point 6); until that reboot there is nothing to do here.
        if (-not (Get-Service vmms -ErrorAction SilentlyContinue)) { Out-Json @{ restart = $true }; return }
        if (-not (Get-VMSwitch -Name $a.switch -ErrorAction SilentlyContinue)) {
            New-VMSwitch -Name $a.switch -SwitchType Internal | Out-Null
        }
        $if = Get-NetAdapter -Name "vEthernet ($($a.switch))"
        if (-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $a.hostAddress -ErrorAction SilentlyContinue)) {
            New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $a.hostAddress -PrefixLength 24 | Out-Null
        }
        # No NAT (M9, D-035): the box's only way out is the egress proxy on
        # the host's address. A NAT an older Sluse made for our prefix goes,
        # or the box would keep a second way out beside the proxy.
        Get-NetNat -ErrorAction SilentlyContinue | Where-Object InternalIPInterfaceAddressPrefix -eq $a.prefix | Remove-NetNat -Confirm:$false
        # The host's own Sluse ports (D-029), kept from Windows' dynamic
        # allocation, so Hyper-V and WinNAT cannot take them. A reservation
        # made by an administrator (marked *) does not stop our own bind; a
        # range Windows reserved for itself does, and is named.
        $excluded = netsh int ipv4 show excludedportrange protocol=tcp | ForEach-Object {
            if ($_ -match '^\s*(\d+)\s+(\d+)\s*(\*)?') { [pscustomobject]@{ Start = [int]$Matches[1]; End = [int]$Matches[2]; Administered = [bool]$Matches[3] } }
        }
        foreach ($p in @($a.hostPorts)) {
            $part = $a.parts."$p"
            $cover = @($excluded | Where-Object { $_.Start -le $p -and $_.End -ge $p })
            $taken = $cover | Where-Object { -not $_.Administered } | Select-Object -First 1
            if ($taken) {
                throw ("port $p ($part) is inside $($taken.Start)-$($taken.End), which Windows reserved for Hyper-V or WinNAT, " +
                       "so the $part cannot listen on it. As an administrator: net stop winnat; sluse device init; net start winnat")
            }
            if (-not $cover) {
                netsh int ipv4 add excludedportrange protocol=tcp startport=$p numberofports=1 store=persistent | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "port $p ($part): Windows would not reserve it (netsh exited $LASTEXITCODE)" }
            }
        }
        # The box reaches Sluse Gate on the host's address, on the host's
        # Sluse ports (D-029), for Gate Front's binary only: Front listens for
        # the box and runs its proxy; Gate Core faces no network (D-071).
        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $FirewallRule -Group 'Sluse' -Direction Inbound -Action Allow `
            -Description "Lets the Sluse boxes on this computer reach Sluse Gate on the host-only network Sluse boxes, 192.168.77.0/24, for sluse-gate-front.exe only. Sluse adds and removes this rule." `
            -Program $a.gate -Protocol TCP -LocalPort @($a.hostPorts) -LocalAddress $a.hostAddress -Profile Any | Out-Null
        Set-SluseLog
        Out-Json @{ restart = $false }
    }
    'event-log' {
        Set-SluseLog
        Out-Json @{ log = 'Sluse' }
    }
    'device-remove' {
        # Uninstall leaves nothing: every box and the build VM, their disks
        # with them, the switch, the NAT, the rule, the Event Log source and
        # the data directory. Each part on its own, so one that cannot be
        # removed does not keep the rest.
        # A list the helper adds to: a scriptblock reads its caller's
        # variables, so this needs no scope modifier.
        $failed = [System.Collections.Generic.List[string]]::new()
        $part = { param($what, $do) try { & $do } catch { $failed.Add("${what}: $_") } }
        & $part 'the boxes' {
            if (Get-Service vmms -ErrorAction SilentlyContinue) {
                foreach ($vm in Get-VM | Where-Object Name -like 'sluse-*') {
                    Stop-VM -VM $vm -TurnOff -Force -ErrorAction SilentlyContinue
                    Remove-VM -VM $vm -Force
                }
                Get-VMSwitch -Name $a.switch -ErrorAction SilentlyContinue | Remove-VMSwitch -Force
            }
        }
        & $part 'the NAT' { Get-NetNat -ErrorAction SilentlyContinue | Where-Object InternalIPInterfaceAddressPrefix -eq $a.prefix | Remove-NetNat -Confirm:$false }
        & $part 'the port reservations' {
            foreach ($p in @($a.hostPorts)) { netsh int ipv4 delete excludedportrange protocol=tcp startport=$p numberofports=1 | Out-Null }
        }
        & $part 'the firewall rule' { Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
        & $part 'the Event Log' {
            if ([Diagnostics.EventLog]::Exists('Sluse')) { Remove-EventLog -LogName 'Sluse' }
            if ([Diagnostics.EventLog]::SourceExists('Sluse')) { Remove-EventLog -Source 'Sluse' }
        }
        # Read-only bases included, which -Force removes.
        & $part 'the data directory' { if ($a.root -and (Test-Path $a.root)) { Remove-Item -Recurse -Force $a.root } }
        if ($failed.Count) { throw ($failed -join '; ') }
        Out-Json @{ removed = $true }
    }
    'guest-checks' {
        # Preflight's guest checks, asked of Hyper-V (slice 5). Gate Core's
        # gate takes these from the service, which is the one that can ask.
        $vm = Get-VM -Name $a.vm
        $nics = @(Get-VMNetworkAdapter -VMName $a.vm)
        $switch = Get-VMSwitch -Name $a.switch -ErrorAction SilentlyContinue
        $onSwitch = @(Get-VMNetworkAdapter -All | Where-Object SwitchName -eq $a.switch | ForEach-Object VMName | Sort-Object -Unique)
        # Another user's box, switched off, is not on the segment: one box runs
        # at a time (D-027 design point 3), and the service keeps to that. Any
        # other state (running, saved, paused) counts (L1, 2026-09-30).
        $others = @($onSwitch | Where-Object { $_ -ne $a.vm } | Where-Object { (Get-VM -Name $_).State -ne 'Off' })
        Out-Json @{
            hypervisorGuest = ($vm.Generation -eq 2)
            hostOnlySegment = ($switch -and $switch.SwitchType -eq 'Internal' -and $nics.Count -gt 0 -and
                               -not ($nics | Where-Object SwitchName -ne $a.switch) -and
                               $others.Count -eq 0)
            enhancedSessionDisabled = (-not (Get-VMHost).EnableEnhancedSessionMode)
            guestServicesOff = (-not (Get-VMIntegrationService -VMName $a.vm -Name 'Guest Service Interface').Enabled)
            detail = "switch $($a.switch) ($($switch.SwitchType)); on it: $($onSwitch -join ', '); not off besides this box: $(if ($others) { $others -join ', ' } else { 'none' }); the box's NICs: $(($nics | ForEach-Object SwitchName) -join ', ')"
        }
    }
    default { throw "unknown verb: $($a.verb)" }
}
