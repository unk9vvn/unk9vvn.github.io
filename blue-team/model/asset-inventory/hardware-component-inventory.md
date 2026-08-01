# Hardware Component Inventory

## Cheat Sheet

### Windows Local Hardware Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Gather System, Base Board, BIOS, CPU, Memory, Network Adapters, Disks, TPM and Secure Boot Information
{% endhint %}

```ps1
$computerSystem        = Get-CimInstance -ClassName Win32_ComputerSystem
$computerSystemProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct
$baseBoard             = Get-CimInstance -ClassName Win32_BaseBoard
$bios                  = Get-CimInstance -ClassName Win32_BIOS
$processors            = Get-CimInstance -ClassName Win32_Processor
$memoryModules         = Get-CimInstance -ClassName Win32_PhysicalMemory
$networkAdapters       = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter }
$physicalDisks         = Get-PhysicalDisk
$tpm                   = Get-Tpm
$secureBoot            = Confirm-SecureBootUEFI

$inventory = [PSCustomObject]@{
    Hostname = $env:COMPUTERNAME

    System = [PSCustomObject]@{
        Manufacturer = $computerSystem.Manufacturer
        Model        = $computerSystem.Model
        TotalMemory  = $computerSystem.TotalPhysicalMemory
        UUID         = $computerSystemProduct.UUID
        Vendor       = $computerSystemProduct.Vendor
        Version      = $computerSystemProduct.Version
    }

    BaseBoard = [PSCustomObject]@{
        Manufacturer = $baseBoard.Manufacturer
        Product      = $baseBoard.Product
        SerialNumber = $baseBoard.SerialNumber
    }

    BIOS = [PSCustomObject]@{
        Manufacturer = $bios.Manufacturer
        Version      = $bios.SMBIOSBIOSVersion
        SerialNumber = $bios.SerialNumber
        ReleaseDate  = $bios.ReleaseDate
    }

    CPU = $processors | ForEach-Object {
        [PSCustomObject]@{
            Name                      = $_.Name
            Manufacturer              = $_.Manufacturer
            NumberOfCores             = $_.NumberOfCores
            NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
        }
    } | Sort-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors -Unique

    Memory = $memoryModules | ForEach-Object {
        [PSCustomObject]@{
            Manufacturer = $_.Manufacturer
            PartNumber   = $_.PartNumber
            SerialNumber = $_.SerialNumber
            Capacity     = $_.Capacity
            Speed        = $_.Speed
        }
    } | Sort-Object Manufacturer, PartNumber, SerialNumber, Capacity, Speed -Unique

    NetworkAdapters = $networkAdapters | ForEach-Object {
        [PSCustomObject]@{
            Name         = $_.Name
            Manufacturer = $_.Manufacturer
            MACAddress   = $_.MACAddress
            Speed        = $_.Speed
            NetEnabled   = $_.NetEnabled
            PNPDeviceID  = $_.PNPDeviceID
        }
    } | Sort-Object MACAddress, PNPDeviceID -Unique

    Disks = $physicalDisks | ForEach-Object {
        [PSCustomObject]@{
            Source       = 'Get-PhysicalDisk'
            Name         = $_.FriendlyName
            SerialNumber = $_.SerialNumber
            BusType      = $_.BusType
            Size         = $_.Size
            MediaType    = $_.MediaType
            HealthStatus = $_.HealthStatus
        }
    } | Sort-Object SerialNumber, Name, Size -Unique

    TPM = [PSCustomObject]@{
        TpmPresent          = $tpm.TpmPresent
        TpmReady            = $tpm.TpmReady
        ManufacturerId      = $tpm.ManufacturerId
        ManufacturerVersion = $tpm.ManufacturerVersion
    }

    SecureBoot = [PSCustomObject]@{
        Enabled = $secureBoot
    }
}

$outputDirectory = 'C:\Hardware Inventory'

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

$outputPath = Join-Path `
    -Path $outputDirectory `
    -ChildPath "$env:COMPUTERNAME-hardware-inventory.json"

$inventory |
    ConvertTo-Json -Depth 6 |
    Out-File -LiteralPath $outputPath -Encoding utf8

Write-Host "Inventory saved: $outputPath" -ForegroundColor Yellow
```

{% hint style="info" %}
Save & Execute (Run as administrator)
{% endhint %}

```powershell
notepad .\local-hardware-inventory.ps1
.\local-hardware-inventory.ps1
```

### Windows Remote Hardware Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Gather System, Base Board, BIOS, CPU, Memory, Network Adapters, Disks, TPM and Secure Boot Information
{% endhint %}

```ps1
# 1. Get computer names from user input
$ComputerNameInput = Read-Host "Enter computer names separated by comma, for example HOST01,HOST02,HOST03"

$ComputerName = @(
    $ComputerNameInput -split ',' |
        ForEach-Object {
            $_.Trim().
                Replace("`r", "").
                Replace("`n", "").
                Replace("[", "").
                Replace("]", "")
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
)

if ($ComputerName.Count -eq 0) {
    throw "No computer names were provided."
}

# 2. Set output directory
$OutputDirectory = 'C:\Hardware Inventory'

# Ensure the output directory exists
if (-not (Test-Path -Path $OutputDirectory)) {
    try {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Gray
    }
    catch {
        throw "Failed to create directory $OutputDirectory. Please run as Administrator."
    }
}

Write-Host "Validated target systems: $($ComputerName -join ', ')" -ForegroundColor Cyan

# 3. Function to prompt for credentials if the connection fails
function Read-CliCredentialForTarget {
    param([Parameter(Mandatory = $true)][string]$Target)
    Write-Host ""
    Write-Host "Enter credentials for target: $Target" -ForegroundColor Cyan
    $UserName = Read-Host "Username for $Target (e.g., DOMAIN\User or $Target\User)"
    $Password = Read-Host "Password for $Target" -AsSecureString
    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

# 4. Inventory script to be executed on the remote target
$InventoryScript = {
    # Helper to suppress errors for specific CIM/WMI queries
    function Get-SafeData {
        param([scriptblock]$Script)
        try { & $Script } catch { $null }
    }

    $computerSystem        = Get-SafeData { Get-CimInstance -ClassName Win32_ComputerSystem }
    $computerSystemProduct = Get-SafeData { Get-CimInstance -ClassName Win32_ComputerSystemProduct }
    $baseBoard             = Get-SafeData { Get-CimInstance -ClassName Win32_BaseBoard }
    $bios                  = Get-SafeData { Get-CimInstance -ClassName Win32_BIOS }
    $processors            = Get-SafeData { Get-CimInstance -ClassName Win32_Processor }
    $memoryModules         = Get-SafeData { Get-CimInstance -ClassName Win32_PhysicalMemory }
    $networkAdapters       = Get-SafeData { Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter } }
    $physicalDisks         = Get-SafeData { Get-PhysicalDisk }
    $tpm                   = Get-SafeData { Get-Tpm }
    $secureBoot            = Get-SafeData { Confirm-SecureBootUEFI }

    [PSCustomObject]@{
        Hostname = $env:COMPUTERNAME
        System = [PSCustomObject]@{
            Manufacturer = $computerSystem.Manufacturer
            Model        = $computerSystem.Model
            TotalMemory  = $computerSystem.TotalPhysicalMemory
            UUID         = $computerSystemProduct.UUID
            Vendor       = $computerSystemProduct.Vendor
            Version      = $computerSystemProduct.Version
        }
        BaseBoard = [PSCustomObject]@{ Manufacturer = $baseBoard.Manufacturer; Product = $baseBoard.Product; SerialNumber = $baseBoard.SerialNumber }
        BIOS = [PSCustomObject]@{ Manufacturer = $bios.Manufacturer; Version = $bios.SMBIOSBIOSVersion; SerialNumber = $bios.SerialNumber; ReleaseDate = $bios.ReleaseDate }
        CPU = @( $processors | ForEach-Object { [PSCustomObject]@{ Name=$_.Name; Manufacturer=$_.Manufacturer; NumberOfCores=$_.NumberOfCores; NumberOfLogicalProcessors=$_.NumberOfLogicalProcessors } } )
        Memory = @( $memoryModules | ForEach-Object { [PSCustomObject]@{ Manufacturer=$_.Manufacturer; PartNumber=$_.PartNumber; SerialNumber=$_.SerialNumber; Capacity=$_.Capacity; Speed=$_.Speed } } )
        NetworkAdapters = @( $networkAdapters | ForEach-Object { [PSCustomObject]@{ Name=$_.Name; Manufacturer=$_.Manufacturer; MACAddress=$_.MACAddress; Speed=$_.Speed; NetEnabled=$_.NetEnabled; PNPDeviceID=$_.PNPDeviceID } } )
        Disks = @( $physicalDisks | ForEach-Object { [PSCustomObject]@{ Source='Get-PhysicalDisk'; Name=$_.FriendlyName; SerialNumber=$_.SerialNumber; BusType=$_.BusType; Size=$_.Size; MediaType=$_.MediaType; HealthStatus=$_.HealthStatus } } )
        TPM = [PSCustomObject]@{ TpmPresent=$tpm.TpmPresent; TpmReady=$tpm.TpmReady; ManufacturerId=$tpm.ManufacturerId; ManufacturerVersion=$tpm.ManufacturerVersion }
        SecureBoot = [PSCustomObject]@{ Enabled = $secureBoot }
    }
}

# 5. Loop through all targets
$results = @()
foreach ($Target in $ComputerName) {
    Write-Host "`nProcessing target: $Target" -ForegroundColor Cyan
    $result = $null

    # Attempt 1: Try current user context
    try {
        $result = Invoke-Command -ComputerName $Target -ScriptBlock $InventoryScript -ErrorAction Stop
        if ($null -ne $result) {
            $results += $result
            Write-Host "Success (Current Context): $Target" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Current context failed for $Target, requesting credentials..." -ForegroundColor DarkGray
    }

    # Attempt 2: Use provided credentials if the first attempt failed
    if ($null -eq $result) {
        try {
            $TargetCredential = Read-CliCredentialForTarget -Target $Target
            $result = Invoke-Command -ComputerName $Target -ScriptBlock $InventoryScript -Credential $TargetCredential -ErrorAction Stop
            if ($null -ne $result) {
                $results += $result
                Write-Host "Success (Provided Credentials): $Target" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Failed to collect from $Target : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 6. Save results to disk
foreach ($result in $results) {
    if (-not [string]::IsNullOrWhiteSpace($result.Hostname)) {
        $outputPath = Join-Path -Path $OutputDirectory -ChildPath "$($result.Hostname)-hardware-inventory.json"
        $result | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputPath -Encoding utf8
        Write-Host "Inventory saved: $outputPath" -ForegroundColor Yellow
    }
}
```

{% hint style="info" %}
Save & Execute (Run as administrator)
{% endhint %}

```powershell
notepad .\remote-hardware-inventory.ps1
.\remote-hardware-inventory.ps1
```

### Linux Local Hardware Inventory

#### Bash

{% hint style="info" %}
Gather BIOS, CPU, PCI, Disks, Memory, Network Adapters and Hardware Information
{% endhint %}

```bash
#!/usr/bin/env bash

set -u

HOSTNAME_SHORT="$(hostname)"
OUTPUT_FILE="${HOSTNAME_SHORT}-hardware-inventory.txt"

run_section() {
    local title="$1"
    shift

    {
        echo
        echo "============================================================"
        echo "=== ${title} ==="
        echo "============================================================"
    } | tee -a "$OUTPUT_FILE"

    "$@" 2>&1 | tee -a "$OUTPUT_FILE"
}

run_memory_dmidecode() {
    sudo dmidecode -t memory | awk '
BEGIN { RS=""; ORS="\n\n" }
$0 !~ /Installed Size:[[:space:]]*Not Installed/ &&
$0 !~ /Size:[[:space:]]*No Module Installed/ { print }
'
}

: > "$OUTPUT_FILE"

echo "Linux Hardware Inventory" | tee -a "$OUTPUT_FILE"
echo "Hostname: ${HOSTNAME_SHORT}" | tee -a "$OUTPUT_FILE"
echo "Collection Time: $(date -Is)" | tee -a "$OUTPUT_FILE"

run_section "BIOS INFO" sudo dmidecode -t bios

run_section "CPU INFO" lscpu

run_section "PCI INFO" lspci

run_section "DISK INFO" lsblk

{
    echo
    echo "============================================================"
    echo "=== MEMORY INFO DMIDECODE ==="
    echo "============================================================"
} | tee -a "$OUTPUT_FILE"

run_memory_dmidecode 2>&1 | tee -a "$OUTPUT_FILE"

run_section "MEMORY INFO FREE" free -h

run_section "NETWORK INFO" ip addr

run_section "LSHW JSON" sudo lshw -json

echo
echo "Inventory text output saved to: ${OUTPUT_FILE}"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x local-hardware-inventory.sh
./local-hardware-inventory.sh
```

### Linux Rempte Hardware Inventory (SSH)

#### Bash

{% hint style="info" %}
Gather BIOS, CPU, PCI, Disks, Memory, Network Adapters and Hardware Information
{% endhint %}

```bash
#!/bin/bash

# Usage check
if [ -z "$1" ]; then
    echo "Usage: $0 <user@remote-target-ip>"
    echo "Example: $0 ubuntu-user1@192.168.109.150"
    exit 1
fi

# Configuration
TARGET="$1"
LOCAL_DIR="./hardware_inventory_results"
mkdir -p "$LOCAL_DIR"

echo "Connecting to $TARGET to perform hardware inventory..."

# Execute command block remotely.
# - ssh -t allocates a TTY so sudo can ask for a password if needed.
# - The inventory file is created on the remote host using its hostname.
ssh -t "$TARGET" '
    REMOTE_HOSTNAME=$(hostname)
    FILE_NAME="${REMOTE_HOSTNAME}-hardware-inventory.txt"

    (
        echo "=== BIOS INFO ==="
        sudo dmidecode -t bios

        echo -e "\n\n=== CPU INFO ==="
        lscpu

        echo -e "\n\n=== PCI INFO ==="
        lspci

        echo -e "\n\n=== Disk INFO ==="
        lsblk

        echo -e "\n\n=== MEMORY INFO (DMIDECODE) ==="
        sudo dmidecode -t memory | awk '"'"'BEGIN { RS=""; ORS="\n\n" } $0 !~ /Installed Size:[[:space:]]*Not Installed/ && $0 !~ /Size:[[:space:]]*No Module Installed/ { print }'"'"'

        echo -e "\n\n=== MEMORY INFO (FREE) ==="
        free -h

        echo -e "\n\n=== NETWORK INFO ==="
        ip addr

        echo -e "\n\n=== LSHW (JSON) ==="
        sudo lshw -json
    ) > "$FILE_NAME"
'

# Extract the hostname from the remote machine to verify the filename for SCP
REMOTE_HOST_NAME=$(ssh "$TARGET" "hostname")

# Retrieve the file
echo "Retrieving ${REMOTE_HOST_NAME}-hardware-inventory.txt..."
scp "$TARGET:${REMOTE_HOST_NAME}-hardware-inventory.txt" "$LOCAL_DIR/"

# Cleanup: Remove file from remote host
echo "Cleaning up remote host..."
ssh "$TARGET" "rm -f '${REMOTE_HOST_NAME}-hardware-inventory.txt'"

echo "Inventory complete. Saved to: $LOCAL_DIR/${REMOTE_HOST_NAME}-hardware-inventory.txt"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x remote-hardware-inventory.sh
./remote-hardware-inventory.sh {user@ip}
```

### Cisco Products

#### General information

```
show version
```

#### Installed subslots and cards

```
show platform
```

#### Memory summary

```
show memory statistics
```
