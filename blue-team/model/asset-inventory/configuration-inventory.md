# Configuration Inventory

## Checklist

* [ ] Always check the configuration files of important software.

## Cheat Sheet

#### [Nmap](https://nmap.org/) & [naabu](https://github.com/projectdiscovery/naabu)

{% hint style="info" %}
Scan to find live IPs and Ports
{% endhint %}

```bash
#!/bin/bash

# Check if the network range is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <network_range>"
    echo "Example: $0 192.168.100.0/24"
    exit 1
fi

# Define your parameters
network="$1"  # Get the target network range from command line
temp_dir="/tmp"
naabu_output="$temp_dir/naabu.txt"
alive_ips_file="$temp_dir/alive_ips.txt"
banners_file="$temp_dir/banners.txt"
host_ports_map="$temp_dir/host-ports.map"
BH_THREAD=10  # Max concurrent nmap jobs

# Step 1: Scan for alive IPs
echo "Scanning for alive IPs in $network..."
nmap -sn "$network" | grep 'Nmap scan report for' | awk '{print $5}' > "$alive_ips_file"

# Step 2: Find open ports with Naabu
echo "Finding open ports with Naabu..."
naabu -list "$alive_ips_file" -p - -c 200 -rate 1000 -silent -o "$naabu_output"

# Step 3: Deduplicate host:port lines and construct host-ports mapping
echo "Deduplicating host:port lines..."
awk -F: '!seen[$0]++{           # de-duplicate host:port lines
           host=$1; port=$2
           ports[host]=ports[host] port ","
         }
         END{
           for(h in ports){
             sub(/,$/,"",ports[h])   # strip trailing comma
             printf "%s:%s\n", h, ports[h]
           }
         }' "$naabu_output" > "$host_ports_map"

# Step 4: Read hosts and ports
while IFS=: read -r host port_list; do
    [ -z "$host" ] || [ -z "$port_list" ] && continue

    {
        echo "Scanning $host for ports: $port_list..."
        nmap -n -sS -sV --mtu 5000 -T4 -Pn \
             -p "$port_list" "$host" >> "$banners_file" 2>&1
    } &

    # Store the process ID
    nmap_pids+=($!)

    # Limit concurrent nmap jobs
    while [ $(jobs -r | wc -l) -ge ${BH_THREAD} ]; do
        sleep 1
    done

done < "$host_ports_map"

# Wait for all Nmap jobs to finish
wait "${nmap_pids[@]}"

echo "Scanning complete. Processing results..."

filtered_output="$temp_dir/scan-results.txt"

awk '
/^Nmap scan report for/ {
    print ""
    print $0
    next
}
/^PORT[[:space:]]+STATE/ { print; next }
/^[0-9]+\/(tcp|udp)/ { print; next }
' "$banners_file" > "$filtered_output"

echo "Clean output saved to $filtered_output"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo nano subnet-scan.sh;sudo ./subnet-scan.sh $TARGET
```

### SNMP

#### [nmap](https://github.com/nmap/nmap)

{% hint style="info" %}
Identify SNMP
{% endhint %}

```bash
nmap -p 161 -sU -sV –mtu 5000 –script=snmp-info $TARGET
```

{% hint style="info" %}
Enumerate SNMP OIDs with community string
{% endhint %}

```bash
snmpwalk -v 1 -c public $TARGET > /tmp/snmpv1-current.txt
```

```bash
snmpwalk -v 2c -c public $TARGET > /tmp/snmpv2c-current.txt
```

```bash
snmpwalk -v3 -u snmpuser -l authPriv -a SHA -A AUTH_PASS \
-x AES -X PRIV_PASS $TARGET > /tmp/snmpv3-current.txt
```

{% hint style="info" %}
Drift Detection
{% endhint %}

```bash
diff snmpv1-baseline.txt /tmp/snmpv1-current.txt
```

```bash
diff snmpv2c-baseline.txt /tmp/snmpv2c-current.txt
```

### Local & Remote Windows Configuration Inventory

{% hint style="info" %}
Collect Windows security, access, and automation configuration data, including Microsoft Defender status, BitLocker volumes, process mitigation settings, audit policy, WinRM configuration, and scheduled task details
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows Configuration Inventory Script.

.DESCRIPTION
    Collects Windows configuration data from local and remote hosts and
    writes one pretty-printed JSON file per host.

.EXAMPLE
    .\conf-inv.ps1

.EXAMPLE
    .\conf-inv.ps1 HOST-01,HOST-02,192.168.1.10

.OUTPUT
    <script-directory>\inventory_results\<hostname>-configuration_inventory_results.json
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Targets
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

# Resolve the output directory relative to the script location.
# This prevents output behavior from depending on the current PowerShell path.
$ScriptRoot = $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
    $ScriptRoot = (Get-Location).Path
}

$OutputDir = Join-Path `
    -Path $ScriptRoot `
    -ChildPath "inventory_results"

try {
    if (-not (Test-Path `
        -LiteralPath $OutputDir `
        -PathType Container `
        -ErrorAction Stop)) {

        New-Item `
            -Path $OutputDir `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop |
            Out-Null
    }
}
catch {
    Write-Host "[!] Cannot create output directory '$OutputDir'." -ForegroundColor Red
    Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Targets)) {
    $ComputerNames = @("localhost")
}
else {
    $ComputerNames = @(
        $Targets -split ',' |
            ForEach-Object {
                $_.Trim().Replace("`r", "").Replace("`n", "")
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Select-Object -Unique
    )
}

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

    $UserName = Read-Host `
        "Username for $Target (Format: DOMAIN\User or $Target\User)"

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw "Username cannot be empty."
    }

    $Password = Read-Host `
        "Password for $Target" `
        -AsSecureString

    return New-Object `
        System.Management.Automation.PSCredential `
        ($UserName, $Password)
}

function Test-LocalTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $NormalizedTarget = $Target.Trim().ToLowerInvariant()
    $LocalComputerName = $env:COMPUTERNAME.Trim().ToLowerInvariant()

    return (
        $NormalizedTarget -eq "localhost" -or
        $NormalizedTarget -eq "." -or
        $NormalizedTarget -eq $LocalComputerName
    )
}

$ConfigurationInventoryScriptBlock = {
    $Results = New-Object System.Collections.Generic.List[object]

    function ConvertTo-PlainObject {
        param(
            [Parameter(Mandatory = $false)]
            [object]$InputObject
        )

        if ($null -eq $InputObject) {
            return $null
        }

        if (
            $InputObject -is [string] -or
            $InputObject -is [char] -or
            $InputObject -is [bool] -or
            $InputObject -is [byte] -or
            $InputObject -is [sbyte] -or
            $InputObject -is [int16] -or
            $InputObject -is [int32] -or
            $InputObject -is [int64] -or
            $InputObject -is [uint16] -or
            $InputObject -is [uint32] -or
            $InputObject -is [uint64] -or
            $InputObject -is [single] -or
            $InputObject -is [double] -or
            $InputObject -is [decimal] -or
            $InputObject -is [datetime] -or
            $InputObject -is [guid] -or
            $InputObject -is [timespan]
        ) {
            return $InputObject
        }

        if ($InputObject -is [System.Enum]) {
            return $InputObject.ToString()
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $DictionaryObject = [ordered]@{}

            foreach ($Key in $InputObject.Keys) {
                $DictionaryObject[[string]$Key] =
                    ConvertTo-PlainObject -InputObject $InputObject[$Key]
            }

            return [PSCustomObject]$DictionaryObject
        }

        if (
            $InputObject -is [System.Collections.IEnumerable] -and
            -not ($InputObject -is [string])
        ) {
            $ArrayObject = New-Object System.Collections.Generic.List[object]

            foreach ($Item in $InputObject) {
                [void]$ArrayObject.Add(
                    (ConvertTo-PlainObject -InputObject $Item)
                )
            }

            return @($ArrayObject.ToArray())
        }

        $ExcludedProperties = @(
            "CimClass",
            "CimInstanceProperties",
            "CimSystemProperties",
            "PSComputerName",
            "RunspaceId",
            "PSShowComputerName",
            "PSSourceJobInstanceId",
            "PSStatus",
            "PSState",
            "PSBeginTime",
            "PSEndTime",
            "PSJobTypeName",
            "Output"
        )

        $PropertyBag = [ordered]@{}

        foreach ($Property in $InputObject.PSObject.Properties) {
            if ($Property.Name -in $ExcludedProperties) {
                continue
            }

            if (-not $Property.IsGettable) {
                continue
            }

            try {
                $PropertyBag[$Property.Name] =
                    ConvertTo-PlainObject -InputObject $Property.Value
            }
            catch {
                $PropertyBag[$Property.Name] = $null
            }
        }

        return [PSCustomObject]$PropertyBag
    }

    function Add-InventoryRecord {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ConfigDomain,

            [Parameter(Mandatory = $true)]
            [string]$ConfigCategory,

            [Parameter(Mandatory = $true)]
            [string]$ConfigItem,

            [Parameter(Mandatory = $true)]
            [string]$CollectionCommand,

            [Parameter(Mandatory = $false)]
            [object]$ConfigValue = $null,

            [Parameter(Mandatory = $false)]
            [string]$CollectionStatus = "success",

            [Parameter(Mandatory = $false)]
            [string]$ErrorMessage = $null
        )

        $InventoryItem = [PSCustomObject]@{
            hostname           = [string]$env:COMPUTERNAME
            asset_type         = "windows_configuration"
            config_domain      = $ConfigDomain
            config_category    = $ConfigCategory
            config_item        = $ConfigItem
            collection_command = $CollectionCommand
            collection_status  = $CollectionStatus
            error_message      = $ErrorMessage
            config_value       = $ConfigValue
            collection_time    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }

        [void]$Results.Add($InventoryItem)
    }

    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Endpoint Protection Configuration" `
            -ConfigItem "Microsoft Defender Computer Status" `
            -CollectionCommand "Get-MpComputerStatus" `
            -ConfigValue (
                ConvertTo-PlainObject -InputObject $DefenderStatus
            )
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Endpoint Protection Configuration" `
            -ConfigItem "Microsoft Defender Computer Status" `
            -CollectionCommand "Get-MpComputerStatus" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    try {
        $BitLockerVolumes = @(
            Get-BitLockerVolume -ErrorAction Stop
        )

        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Disk Encryption Configuration" `
            -ConfigItem "BitLocker Volume Configuration" `
            -CollectionCommand "Get-BitLockerVolume" `
            -ConfigValue (
                ConvertTo-PlainObject -InputObject $BitLockerVolumes
            )
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Disk Encryption Configuration" `
            -ConfigItem "BitLocker Volume Configuration" `
            -CollectionCommand "Get-BitLockerVolume" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    try {
        $SystemMitigation = Get-ProcessMitigation `
            -System `
            -ErrorAction Stop

        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Exploit Protection Configuration" `
            -ConfigItem "System Process Mitigation Configuration" `
            -CollectionCommand "Get-ProcessMitigation -System" `
            -ConfigValue (
                ConvertTo-PlainObject -InputObject $SystemMitigation
            )
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Exploit Protection Configuration" `
            -ConfigItem "System Process Mitigation Configuration" `
            -CollectionCommand "Get-ProcessMitigation -System" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    try {
        $AuditPolicyLines = @(
            auditpol /get /category:* 2>&1 |
                ForEach-Object {
                    $_.ToString()
                }
        )

        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Audit Policy Configuration" `
            -ConfigItem "Advanced Audit Policy Configuration" `
            -CollectionCommand "auditpol /get /category:*" `
            -ConfigValue $AuditPolicyLines
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Security Configuration" `
            -ConfigCategory "Audit Policy Configuration" `
            -ConfigItem "Advanced Audit Policy Configuration" `
            -CollectionCommand "auditpol /get /category:*" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    try {
        $WinRmConfigLines = @(
            winrm get winrm/config 2>&1 |
                ForEach-Object {
                    $_.ToString()
                }
        )

        Add-InventoryRecord `
            -ConfigDomain "Account / Access Configuration" `
            -ConfigCategory "Remote Management Configuration" `
            -ConfigItem "WinRM Service Configuration" `
            -CollectionCommand "winrm get winrm/config" `
            -ConfigValue $WinRmConfigLines
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Account / Access Configuration" `
            -ConfigCategory "Remote Management Configuration" `
            -ConfigItem "WinRM Service Configuration" `
            -CollectionCommand "winrm get winrm/config" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    try {
        $ScheduledTasksLines = @(
            schtasks /query /fo LIST /v 2>&1 |
                ForEach-Object {
                    $_.ToString()
                }
        )

        Add-InventoryRecord `
            -ConfigDomain "Task / Automation Configuration" `
            -ConfigCategory "Scheduled Task Configuration" `
            -ConfigItem "Windows Scheduled Tasks Detailed Configuration" `
            -CollectionCommand "schtasks /query /fo LIST /v" `
            -ConfigValue $ScheduledTasksLines
    }
    catch {
        Add-InventoryRecord `
            -ConfigDomain "Task / Automation Configuration" `
            -ConfigCategory "Scheduled Task Configuration" `
            -ConfigItem "Windows Scheduled Tasks Detailed Configuration" `
            -CollectionCommand "schtasks /query /fo LIST /v" `
            -CollectionStatus "failed" `
            -ErrorMessage $_.Exception.Message
    }

    # The unary comma keeps the complete result array as one pipeline object.
    return ,$Results.ToArray()
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $InventoryRecords = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $InventoryRecords = & $ConfigurationInventoryScriptBlock
        }
        else {
            $InventoryRecords = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $ConfigurationInventoryScriptBlock `
                -ErrorAction Stop
        }
    }
    catch {
        if ($IsLocalTarget) {
            Write-Host `
                "[!] Local inventory collection failed: $($_.Exception.Message)" `
                -ForegroundColor Red

            continue
        }

        Write-Host `
            "[-] Current user context failed for $Target. Requesting credentials..." `
            -ForegroundColor DarkGray
    }

    if ($null -eq $InventoryRecords -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target

            $InventoryRecords = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $ConfigurationInventoryScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host `
                "[!] Failed to collect from ${Target}: $($_.Exception.Message)" `
                -ForegroundColor Red

            continue
        }
    }

    if ($null -eq $InventoryRecords) {
        Write-Host `
            "[!] No inventory result was returned for $Target." `
            -ForegroundColor Red

        continue
    }

    $InventoryRecords = @($InventoryRecords)

    if (
        $InventoryRecords.Count -gt 0 -and
        $null -ne $InventoryRecords[0].hostname -and
        -not [string]::IsNullOrWhiteSpace(
            [string]$InventoryRecords[0].hostname
        )
    ) {
        $FinalHostName = [string]$InventoryRecords[0].hostname
    }

    if ($InventoryRecords.Count -eq 0) {
        Write-Host `
            "[!] No records collected from $Target." `
            -ForegroundColor Yellow

        continue
    }

    $FinalHostName = $FinalHostName.Trim()

    if ([string]::IsNullOrWhiteSpace($FinalHostName)) {
        $FinalHostName = $Target.Trim()
    }

    $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'

    $OutputFilePath = Join-Path `
        -Path $OutputDir `
        -ChildPath "${SafeHostName}-configuration_inventory_results.json"

    try {
        $JsonOutput = $InventoryRecords |
            ConvertTo-Json -Depth 20

        if ([string]::IsNullOrWhiteSpace($JsonOutput)) {
            throw "ConvertTo-Json returned an empty result."
        }

        $Utf8NoBom = New-Object `
            System.Text.UTF8Encoding($false)

        [System.IO.File]::WriteAllText(
            $OutputFilePath,
            $JsonOutput,
            $Utf8NoBom
        )

        $FileExists = Test-Path `
            -LiteralPath $OutputFilePath `
            -PathType Leaf `
            -ErrorAction Stop

        if (-not $FileExists) {
            throw "The output file was not created."
        }

        $OutputFile = Get-Item `
            -LiteralPath $OutputFilePath `
            -ErrorAction Stop

        if ($OutputFile.Length -eq 0) {
            throw "The output file is empty."
        }

        Write-Host `
            "[+] Inventory saved for ${FinalHostName}: $($OutputFile.FullName)" `
            -ForegroundColor Green

        Write-Host `
            "[+] Total records collected: $($InventoryRecords.Count)" `
            -ForegroundColor Gray
    }
    catch {
        Write-Host `
            "[!] Failed to write output for ${FinalHostName}: $($_.Exception.Message)" `
            -ForegroundColor Red

        Write-Host `
            "[!] Expected output path: $OutputFilePath" `
            -ForegroundColor Yellow

        continue
    }
}

Write-Host "`n[*] All tasks completed." -ForegroundColor White
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
notepad .\configuration-inventory.ps1
.\configuration-inventory.ps1 # Local Inventory
.\configuration-inventory.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### System Configuration

#### [Lynis (Linux)](https://github.com/CISOfy/lynis)

```bash
lynis
```

#### [Hardentools (Windows)](https://github.com/hardentools/hardentools)

```bash
hardentools-cli.exe
```
