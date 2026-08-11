# System Dependency Mapping

## Checklist

* [ ] You can use the outputs of the Service Dependency Mapping cheat sheets and the Network Mapping topics along with the outputs of the cheat sheets in this section, since these topics are related and can help with a more accurate analysis

## Cheatsheet

### Local & Remote Windows System Dependency Mapping

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect process metadata, active TCP/UDP network connections with associated process names, loaded process modules, driver inventories, startup commands and scheduled tasks
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows System Dependency Mapping Inventory Script.

.DESCRIPTION
    Collects Windows system dependency mapping data for local and remote hosts.

    For each host, the script collects:
    - Process data
    - TCP connections with owning process name
    - UDP endpoints with owning process name
    - Loaded process modules grouped by process
    - Driver inventory
    - Startup commands
    - Scheduled tasks

.EXAMPLE
    .\system-dependency-mapping.ps1

.EXAMPLE
    .\system-dependency-mapping.ps1 unk9vvn,WIN-E31P99E3C3J

.EXAMPLE
    .\system-dependency-mapping.ps1 unk9vvn WIN-E31P99E3C3J

.EXAMPLE
    .\system-dependency-mapping.ps1 "unk9vvn,WIN-E31P99E3C3J"

.OUTPUT
    inventory_results\<hostname>-system-dependency-mapping.json
#>

param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Targets
)

$OutputDir = "inventory_results"

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

function Convert-TargetsToComputerNames {
    param(
        [string[]]$RawTargets
    )

    if ($null -eq $RawTargets -or $RawTargets.Count -eq 0) {
        return @("localhost")
    }

    $ComputerNameList = @()

    foreach ($RawTarget in $RawTargets) {
        if ([string]::IsNullOrWhiteSpace($RawTarget)) {
            continue
        }

        $CleanTarget = $RawTarget.Trim().Replace("`r", " ").Replace("`n", " ")
        $Parts = $CleanTarget -split '[,\s;]+'

        foreach ($Part in $Parts) {
            $ComputerName = $Part.Trim()

            if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
                $ComputerNameList += $ComputerName
            }
        }
    }

    $ComputerNameList = @(
        $ComputerNameList |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Select-Object -Unique
    )

    if ($ComputerNameList.Count -eq 0) {
        return @("localhost")
    }

    return $ComputerNameList
}

$ComputerNames = Convert-TargetsToComputerNames -RawTargets $Targets

if ($ComputerNames.Count -eq 0) {
    Write-Host "[!] No valid computer name was provided." -ForegroundColor Red
    exit 1
}

function Read-CliCredentialForTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Write-Host "`n[!] Credentials required for $Target" -ForegroundColor Yellow
    $UserName = Read-Host "Username for $Target (Format: DOMAIN\User or $Target\User)"
    $Password = Read-Host "Password for $Target" -AsSecureString

    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

function Test-LocalTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $NormalizedTarget = $Target.Trim().ToLower()
    $LocalComputerName = $env:COMPUTERNAME.ToLower()

    if ($NormalizedTarget -eq "localhost") {
        return $true
    }

    if ($NormalizedTarget -eq ".") {
        return $true
    }

    if ($NormalizedTarget -eq $LocalComputerName) {
        return $true
    }

    return $false
}

$SystemDependencyMappingScriptBlock = {
    $HostName = $env:COMPUTERNAME

    $Processes = Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine

    $TcpConnections = Get-NetTCPConnection | ForEach-Object {
        $ProcessObject = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State.ToString()
            OwningProcess = $_.OwningProcess
            ProcessName   = $ProcessObject.ProcessName
        }
    }

    $UdpEndpoints = Get-NetUDPEndpoint | ForEach-Object {
        $ProcessObject = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            OwningProcess = $_.OwningProcess
            ProcessName   = $ProcessObject.ProcessName
        }
    }

    $ProcessModules = Get-Process | ForEach-Object {
        $p = $_

        try {
            $ModuleObjects = @(
                $p.Modules | ForEach-Object {
                    [PSCustomObject]@{
                        ModuleName = $_.ModuleName
                        FileName   = $_.FileName
                    }
                }
            )

            [PSCustomObject]@{
                ProcessName = $p.ProcessName
                ProcessId   = $p.Id
                Modules     = $ModuleObjects
            }
        }
        catch {
            [PSCustomObject]@{
                ProcessName = $p.ProcessName
                ProcessId   = $p.Id
                Modules     = @()
                Error       = $_.Exception.Message
            }
        }
    }

    $Drivers = driverquery /v /fo csv | ConvertFrom-Csv | Select-Object `
        "Module Name", "Display Name", "Driver Type", "Start Mode", "State", "Status", "Service Name", "Path", "Init", "Description"

    $StartupCommands = Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, User, Location

    $ScheduledTasks = Get-ScheduledTask | Select-Object `
        TaskName,
        TaskPath,
        @{
            Name = "State"
            Expression = {
                $_.State.ToString()
            }
        },
        @{
            Name = "Actions"
            Expression = {
                $_.Actions.Execute
            }
        }

    return [PSCustomObject]@{
        hostname         = $HostName
        collected_at     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        asset_type       = "windows_system_dependency_mapping"
        process_count    = @($Processes).Count
        tcp_count        = @($TcpConnections).Count
        udp_count        = @($UdpEndpoints).Count
        driver_count     = @($Drivers).Count
        startup_count    = @($StartupCommands).Count
        scheduled_count  = @($ScheduledTasks).Count
        processes        = $Processes
        tcp_connections  = $TcpConnections
        udp_endpoints    = $UdpEndpoints
        process_modules  = $ProcessModules
        drivers          = $Drivers
        startup_commands = $StartupCommands
        scheduled_tasks  = $ScheduledTasks
    }
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $ResultObject = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $ResultObject = & $SystemDependencyMappingScriptBlock
        }
        else {
            $ResultObject = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $SystemDependencyMappingScriptBlock `
                -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[-] Current user context failed for $Target. Requesting credentials..." -ForegroundColor DarkGray
    }

    if ($null -eq $ResultObject -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target

            $ResultObject = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $SystemDependencyMappingScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $ResultObject -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local system dependency mapping from ${Target}." -ForegroundColor Red
        continue
    }

    if ($ResultObject.hostname) {
        $FinalHostName = $ResultObject.hostname
    }

    $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
    $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-system-dependency-mapping.json"

    try {
        $ResultObject |
            ConvertTo-Json -Depth 30 |
            Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force

        $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

        Write-Host "[+] System dependency mapping saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
        Write-Host "[+] Processes collected: $($ResultObject.process_count)" -ForegroundColor Gray
        Write-Host "[+] TCP connections collected: $($ResultObject.tcp_count)" -ForegroundColor Gray
        Write-Host "[+] UDP endpoints collected: $($ResultObject.udp_count)" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Failed to write output for ${FinalHostName}: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

Write-Host "`n[*] All tasks completed." -ForegroundColor White
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
notepad system-dependency-mapping.ps1
.\system-dependency-mapping.ps1 # Local Inventory
.\system-dependency-mapping.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```
