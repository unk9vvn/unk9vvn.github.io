# Configuration Inventory

## Check List

* [ ] Review the applications’ configurations set across the network and validate that they are not vulnerable.
*[ ]   Validate that used frameworks and systems are secure and not susceptible to known vulnerabilities due to unmaintained software or default settings and credentials.
*[ ]   Ensure that defaults and known files have been removed.
*[ ]   Review and validate the policy files.
*[ ]   Review the Content-Security-Policy header or meta element to identify misconfigurations.
*[ ]   Make sure application paths are configured correctly.
*[ ]   Assess that the access control configuration for the storage services is properly in place.

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
    Installed software and potential configuration directories inventory.

.DESCRIPTION
    Collects installed software from uninstall registry keys.
    Finds existing potential configuration directories without reading
    configuration file contents.

    Writes one plain-text report per host on the executing computer.

.EXAMPLE
    .\apps-inv.ps1

.EXAMPLE
    .\apps-inv.ps1 -Targets "HOST-01,HOST-02"

.OUTPUTS
    C:\inventory_results\<hostname>-configuration-inventory-results.txt

.NOTES
    Run using 64-bit PowerShell.
    Remote collection requires PowerShell Remoting.
    HKCU and AppData belong to the account performing collection.
    Configuration directories are candidates, not verified settings paths.
    Portable and Microsoft Store applications may not be included.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Targets
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$OutputDir = "C:\inventory_results"

try {
    if (-not (Test-Path -LiteralPath $OutputDir -PathType Container `
                -ErrorAction Stop)) {
        New-Item -Path $OutputDir -ItemType Directory -Force `
            -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Error "Cannot create '$OutputDir': $($_.Exception.Message)"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Targets)) {
    $ComputerNames = @("localhost")
}
else {
    $ComputerNames = @(
        $Targets -split "," |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

if ($ComputerNames.Count -eq 0) {
    Write-Error "No valid target was provided."
    exit 1
}

$CollectSoftware = {
    Set-StrictMode -Version 2.0

    function Get-RegistryText {
        param(
            [AllowNull()]
            [object]$Item,

            [string]$Name
        )

        # Get-ItemProperty can return no object for an empty key.
        if ($null -eq $Item) {
            return ""
        }

        $Property = $Item.PSObject.Properties[$Name]

        if ($null -eq $Property) {
            return ""
        }

        if ($null -eq $Property.Value) {
            return ""
        }

        return [string]$Property.Value
    }

    function Test-SafeDirectoryName {
        param(
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Name
        )

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return $false
        }

        if ($Name -eq "." -or $Name -eq "..") {
            return $false
        }

        return (
            $Name.IndexOfAny(
                [System.IO.Path]::GetInvalidFileNameChars()
            ) -lt 0
        )
    }

    function Find-ConfigurationDirectories {
        param(
            [string]$Name,
            [string]$Publisher,
            [string]$InstallLocation
        )

        $Candidates = New-Object 'System.Collections.Generic.List[string]'
        $DirectoryNames = @($Name)

        # Only use absolute filesystem installation paths.
        $ValidInstallPath = (
            -not [string]::IsNullOrWhiteSpace($InstallLocation) -and
            $InstallLocation -match '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)'
        )

        if ($ValidInstallPath) {
            try {
                $InstallFolderName = Split-Path `
                    -Path $InstallLocation.TrimEnd('\') `
                    -Leaf `
                    -ErrorAction Stop

                if (Test-SafeDirectoryName $InstallFolderName) {
                    $DirectoryNames += $InstallFolderName
                }
            }
            catch {
                Write-Warning "Cannot inspect installation path '$InstallLocation': $($_.Exception.Message)"
            }
        }

        $DirectoryNames = @(
            $DirectoryNames |
                Where-Object { Test-SafeDirectoryName $_ } |
                Select-Object -Unique
        )

        $DataRoots = @(
            @(
                $env:ProgramData
                $env:APPDATA
                $env:LOCALAPPDATA
            ) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                Select-Object -Unique
        )

        foreach ($Root in $DataRoots) {
            foreach ($DirectoryName in $DirectoryNames) {
                try {
                    [void]$Candidates.Add(
                        (Join-Path -Path $Root -ChildPath $DirectoryName `
                            -ErrorAction Stop)
                    )

                    if (Test-SafeDirectoryName $Publisher) {
                        $PublisherRoot = Join-Path `
                            -Path $Root `
                            -ChildPath $Publisher `
                            -ErrorAction Stop

                        [void]$Candidates.Add(
                            (Join-Path -Path $PublisherRoot `
                                -ChildPath $DirectoryName -ErrorAction Stop)
                        )
                    }
                }
                catch {
                    Write-Warning "Cannot build configuration candidate for '$Name': $($_.Exception.Message)"
                }
            }
        }

        if ($ValidInstallPath) {
            foreach ($Subdirectory in @(
                "config", "configs", "configuration", "settings"
            )) {
                try {
                    [void]$Candidates.Add(
                        (Join-Path -Path $InstallLocation `
                            -ChildPath $Subdirectory -ErrorAction Stop)
                    )
                }
                catch {
                    Write-Warning "Cannot build configuration candidate under '$InstallLocation': $($_.Exception.Message)"
                }
            }
        }

        foreach ($Path in ($Candidates.ToArray() | Sort-Object -Unique)) {
            try {
                if (Test-Path -LiteralPath $Path -PathType Container `
                        -ErrorAction Stop) {
                    $Path
                }
            }
            catch {
                Write-Warning "Cannot inspect configuration candidate '$Path': $($_.Exception.Message)"
            }
        }
    }

    if (
        [Environment]::Is64BitOperatingSystem -and
        -not [Environment]::Is64BitProcess
    ) {
        Write-Warning "Collection is running in 32-bit PowerShell; some 64-bit applications may be missing."
    }

    $Roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $Apps = New-Object 'System.Collections.Generic.List[object]'

    foreach ($Root in $Roots) {
        try {
            if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) {
                continue
            }

            # Keep any accessible keys even if another key causes an error.
            $KeyErrors = @()
            $Keys = @(
                Get-ChildItem -LiteralPath $Root `
                    -ErrorAction SilentlyContinue `
                    -ErrorVariable KeyErrors
            )

            foreach ($KeyError in $KeyErrors) {
                Write-Warning "Cannot fully enumerate '$Root': $($KeyError.Exception.Message)"
            }
        }
        catch {
            Write-Warning "Cannot read '$Root': $($_.Exception.Message)"
            continue
        }

        foreach ($Key in $Keys) {
            try {
                $Item = Get-ItemProperty -LiteralPath $Key.PSPath `
                    -ErrorAction Stop

                # Empty registry keys are not application records.
                if ($null -eq $Item) {
                    continue
                }

                $Name = Get-RegistryText -Item $Item -Name "DisplayName"

                if ([string]::IsNullOrWhiteSpace($Name)) {
                    continue
                }

                $InstallLocation = Get-RegistryText `
                    -Item $Item -Name "InstallLocation"

                $InstallLocation = $InstallLocation.Trim().Trim('"')

                if (-not [string]::IsNullOrWhiteSpace($InstallLocation)) {
                    $InstallLocation =
                        [Environment]::ExpandEnvironmentVariables(
                            $InstallLocation
                        )
                }

                [void]$Apps.Add([pscustomobject]@{
                    Name            = $Name.Trim()
                    Version         = Get-RegistryText $Item "DisplayVersion"
                    Publisher       = Get-RegistryText $Item "Publisher"
                    InstallLocation = $InstallLocation
                })
            }
            catch {
                Write-Warning "Cannot read '$($Key.Name)': $($_.Exception.Message)"
            }
        }
    }

    # Preserve installations with different installation paths.
    $SortedApps = @(
        $Apps.ToArray() |
            Sort-Object Name, Version, Publisher, InstallLocation -Unique
    )

    $Results = @(
        foreach ($App in $SortedApps) {
            $ConfigurationPaths = @(
                Find-ConfigurationDirectories `
                    -Name $App.Name `
                    -Publisher $App.Publisher `
                    -InstallLocation $App.InstallLocation
            )

            [pscustomobject]@{
                Name                        = $App.Name
                Version                     = $App.Version
                Publisher                   = $App.Publisher
                InstallLocation             = $App.InstallLocation
                ConfigurationPathCandidates = $ConfigurationPaths
            }
        }
    )

    # Hostname is used only to name the output file.
    [pscustomobject]@{
        Hostname     = [string]$env:COMPUTERNAME
        Applications = $Results
    }
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing: $Target" -ForegroundColor Cyan

    $IsLocal = (
        $Target -eq "." -or
        $Target -eq "localhost" -or
        $Target -eq $env:COMPUTERNAME
    )

    $Inventory = $null

    try {
        if ($IsLocal) {
            $Inventory = & $CollectSoftware
        }
        else {
            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $CollectSoftware `
                -ErrorAction Stop
        }
    }
    catch {
        if ($IsLocal) {
            Write-Warning "Local collection failed: $($_.Exception.Message)"
            continue
        }

        Write-Warning "Remote collection failed: $($_.Exception.Message)"

        try {
            $Credential = Get-Credential `
                -Message "Enter credentials for $Target" `
                -ErrorAction Stop

            if ($null -eq $Credential) {
                throw "Credentials were not provided."
            }

            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $CollectSoftware `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Collection failed for ${Target}: $($_.Exception.Message)"
            continue
        }
    }

    if ($null -eq $Inventory) {
        Write-Warning "No result returned for $Target."
        continue
    }

    $HostNameForFile = [string]$Inventory.Hostname

    if ([string]::IsNullOrWhiteSpace($HostNameForFile)) {
        $HostNameForFile = $Target
    }

    $SafeHostName = $HostNameForFile.Trim() -replace '[\\/:*?"<>|]', '_'

    $OutputFile = Join-Path -Path $OutputDir `
        -ChildPath "${SafeHostName}-configuration-inventory-results.txt"

    $Lines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($App in @($Inventory.Applications)) {
        if ($null -eq $App) {
            continue
        }

        [void]$Lines.Add("Name: $($App.Name)")
        [void]$Lines.Add("Version: $($App.Version)")
        [void]$Lines.Add("Publisher: $($App.Publisher)")

        $Location = [string]$App.InstallLocation

        if ([string]::IsNullOrWhiteSpace($Location)) {
            $Location = "Not registered"
        }

        [void]$Lines.Add("Installation path: $Location")
        [void]$Lines.Add("Potential configuration directories (unverified):")

        $Paths = @(
            $App.ConfigurationPathCandidates |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_)
                } |
                Sort-Object -Unique
        )

        if ($Paths.Count -eq 0) {
            [void]$Lines.Add(
                "  Not found by directory-name matching; settings may exist elsewhere."
            )
        }
        else {
            foreach ($Path in $Paths) {
                [void]$Lines.Add("  $Path")
            }
        }

        [void]$Lines.Add(('-' * 80))
    }

    if ($Lines.Count -eq 0) {
        Write-Warning "No applications collected for $Target; no new report written. Any existing report remains unchanged."
        continue
    }

    try {
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        [System.IO.File]::WriteAllLines(
            $OutputFile,
            $Lines.ToArray(),
            $Utf8NoBom
        )

        $SavedFile = Get-Item -LiteralPath $OutputFile -ErrorAction Stop

        if ($SavedFile.Length -eq 0) {
            throw "The output file is empty."
        }

        Write-Host "[+] Saved: $($SavedFile.FullName)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Cannot write '${OutputFile}': $($_.Exception.Message)"
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
