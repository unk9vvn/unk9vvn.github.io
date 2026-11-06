# Hardware Component Inventory

## Check List

* [ ] Enumerate processors, memory modules, storage devices, system buses, and hardware virtualization components.&#x20;
* [ ] Enumerate NICs, wireless adapters, MAC addresses, network interfaces, and connected peripherals.&#x20;
* [ ] Record hardware manufacturer, model, serial number, firmware version, driver version, and operational status.&#x20;
* [ ] Identify removable media, USB devices, docking stations, biometric devices, and other externally connected components.&#x20;
* [ ] Correlate discovered hardware with hostnames, asset owners, locations, operating systems, and authorized inventory records.&#x20;
* [ ] Detect unknown, disabled, obsolete, modified, or unauthorized hardware components and investigate discrepancies.

## Cheat Sheet

### Local & Remote Windows Hardware Component Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect system chassis metadata, BIOS attributes, motherboard details, CPU core configurations, memory module metrics, physical storage properties, Trusted Platform Module configurations, and Secure Boot status
{% endhint %}

```powershell
<#
.SYNOPSIS
    Comprehensive Windows Hardware Inventory Script.

.DESCRIPTION
    Performs Windows hardware inventory for both local and remote hosts.
    Queries BIOS, CPU, Memory, Disks, TPM, and Secure Boot configurations.
    Handles null-byte cleanup for TPM fields and supports credential fallback.

.EXAMPLE
    .\hardware-component-inventory.ps1 -Targets "unk9vvn,WIN-E31P99E3C3J"

.OUTPUT
    inventory_results\<hostname>-hardware_inventory.json
#>

param(
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [Alias("ComputerName")]
    [object]$Targets
)

$OutputDir = "inventory_results"

# Ensure output directory exists
if (-not (Test-Path -Path $OutputDir)) {
    try {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Host "[!] Failed to create directory $OutputDir. Run as Administrator." -ForegroundColor Red
        exit 1
    }
}

# Determine target systems and handle Array vs String input
$ComputerNames = @()
if ($null -eq $Targets -or [string]::IsNullOrWhiteSpace($Targets.ToString())) {
    $ComputerNames = @("localhost")
}
else {
    # Convert input to string and split by comma to handle unquoted CLI input
    $RawTargets = if ($Targets -is [array]) { $Targets -join ',' } else { $Targets.ToString() }
    $ComputerNames = @(
        $RawTargets -split ',' |
            ForEach-Object {
                $_.Trim().Replace("`r", "").Replace("`n", "").Replace("[", "").Replace("]", "")
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

if ($ComputerNames.Count -eq 0) {
    Write-Host "[!] No valid computer names were provided." -ForegroundColor Red
    exit 1
}

function Read-CliCredentialForTarget {
    param([Parameter(Mandatory = $true)][string]$Target)
    Write-Host "`n[!] Credentials required for ${Target}" -ForegroundColor Yellow
    $UserName = Read-Host "Username for ${Target} (Format: DOMAIN\User or Administrator)"
    $Password = Read-Host "Password for ${Target}" -AsSecureString
    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

function Test-LocalTarget {
    param([Parameter(Mandatory = $true)][string]$Target)
    $NormalizedTarget = $Target.Trim().ToLower()
    $LocalComputerName = $env:COMPUTERNAME.ToLower()
    return ($NormalizedTarget -eq "localhost" -or $NormalizedTarget -eq "." -or $NormalizedTarget -eq $LocalComputerName)
}

$HardwareInventoryScriptBlock = {
    function Get-SafeData {
        param([scriptblock]$Script)
        try { & $Script -ErrorAction Stop } catch { $null }
    }

    # Data Collection
    $cs        = Get-SafeData { Get-CimInstance -ClassName Win32_ComputerSystem }
    $csp       = Get-SafeData { Get-CimInstance -ClassName Win32_ComputerSystemProduct }
    $bb        = Get-SafeData { Get-CimInstance -ClassName Win32_BaseBoard }
    $bios      = Get-SafeData { Get-CimInstance -ClassName Win32_BIOS }
    $procs     = Get-SafeData { Get-CimInstance -ClassName Win32_Processor }
    $mem       = Get-SafeData { Get-CimInstance -ClassName Win32_PhysicalMemory }
    $disks     = Get-SafeData { Get-PhysicalDisk }
    $tpm       = Get-SafeData { Get-Tpm }
    $sb        = Get-SafeData { Confirm-SecureBootUEFI }

    # Clean Null Characters (\u0000) from TPM ManufacturerVersion
    $cleanTpmVer = $null
    if ($null -ne $tpm -and $null -ne $tpm.ManufacturerVersion) {
        $nullChar = [string][char]0
        $cleanTpmVer = $tpm.ManufacturerVersion.Replace($nullChar, "").Trim()
    }

    return [PSCustomObject]@{
        hostname   = $env:COMPUTERNAME
        timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        System     = @{ 
            Manufacturer = $cs.Manufacturer; 
            Model = $cs.Model; 
            UUID = $csp.UUID 
        }
        BIOS       = @{ 
            Vendor = $bios.Manufacturer; 
            Version = $bios.SMBIOSBIOSVersion; 
            Serial = $bios.SerialNumber 
        }
        BaseBoard  = @{ 
            Product = $bb.Product; 
            Serial = $bb.SerialNumber 
        }
        CPU        = $procs | ForEach-Object { @{ Name = $_.Name; Cores = $_.NumberOfCores; Threads = $_.NumberOfLogicalProcessors } }
        Memory     = $mem | ForEach-Object { @{ CapacityGB = [Math]::Round($_.Capacity / 1GB, 2); Speed = $_.Speed; PartNumber = $_.PartNumber.Trim() } }
        Disks      = $disks | ForEach-Object { @{ FriendlyName = $_.FriendlyName; SizeGB = [Math]::Round($_.Size / 1GB, 2); Media = $_.MediaType; Health = $_.HealthStatus } }
        TPM        = @{ 
            Present = if($null -ne $tpm){$tpm.TpmPresent}else{$false}; 
            Ready = if($null -ne $tpm){$tpm.TpmReady}else{$false}; 
            Version = $cleanTpmVer 
        }
        SecureBoot = @{ Enabled = $sb }
    }
}

# Execution Loop
foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: ${Target}" -ForegroundColor Cyan
    $Result = $null
    $IsLocal = Test-LocalTarget -Target $Target

    try {
        if ($IsLocal) {
            $Result = & $HardwareInventoryScriptBlock
        } else {
            $Result = Invoke-Command -ComputerName $Target -ScriptBlock $HardwareInventoryScriptBlock -ErrorAction Stop
        }
    } catch {
        Write-Host "[-] Connection failed for ${Target}. Attempting credential fallback..." -ForegroundColor Gray
    }

    if ($null -eq $Result -and -not $IsLocal) {
        try {
            $Cred = Read-CliCredentialForTarget -Target $Target
            $Result = Invoke-Command -ComputerName $Target -ScriptBlock $HardwareInventoryScriptBlock -Credential $Cred -ErrorAction Stop
        } catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -ne $Result) {
        $FinalHost = if ($null -ne $Result.hostname) { $Result.hostname } else { $Target }
        $SafeName = $FinalHost -replace '[\\/:*?"<>|]', '_'
        $Path = Join-Path $OutputDir "${SafeName}-hardware_inventory.json"
        
        try {
            $Result | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8 -Force
            Write-Host "[+] Inventory saved: $((Get-Item $Path).FullName)" -ForegroundColor Green
        } catch {
            Write-Host "[!] IO Error for ${FinalHost}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n[*] Hardware inventory tasks completed." -ForegroundColor White
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
notepad .\hardware-component-inventory.ps1
.\hardware-component-inventory.ps1 # Local Inventory
.\hardware-component-inventory.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Linux Hardware Component Inventory

#### [dmidecode](https://github.com/mirror/dmidecode) & [lscpu](https://man7.org/linux/man-pages/man1/lscpu.1.html) & [lspci](https://man7.org/linux/man-pages/man8/lspci.8.html) & [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html) & [free](https://man7.org/linux/man-pages/man1/free.1.html) & [ip](https://man7.org/linux/man-pages/man8/ip.8.html) & [lshw](https://github.com/lyonel/lshw)

{% hint style="info" %}
Collect BIOS, CPU, PCI devices, disk (block device), memory slot and usage, network interface, and consolidated LSHW hardware inventory data
{% endhint %}

```bash
#!/usr/bin/env bash

set -u

if [ -z "${1:-}" ]; then
    REMOTE_MODE=false
else
    REMOTE_MODE=true
    TARGET="$1"
fi

collect_inventory() {
    local hostname
    hostname=$(hostname)

    sudo dmidecode -t bios > /tmp/_bios.txt 2>&1
    lscpu > /tmp/_cpu.txt 2>&1
    lspci > /tmp/_pci.txt 2>&1
    lsblk --json > /tmp/_disk.json 2>&1
    sudo dmidecode -t memory 2>&1 | awk 'BEGIN{RS="";ORS="\n\n"} $0!~/Installed Size:[[:space:]]*Not Installed/ && $0!~/Size:[[:space:]]*No Module Installed/{print}' > /tmp/_mem.txt
    free -h > /tmp/_free.txt 2>&1
    ip addr > /tmp/_net.txt 2>&1
    sudo lshw -json > /tmp/_lshw.json 2>&1

    python3 - <<'PYEOF'
import json, re, socket

def read(path):
    try:
        with open(path) as f: return f.read().strip()
    except: return ""

def parse_lshw():
    try:
        with open("/tmp/_lshw.json") as f: return json.load(f)
    except: return {}

def parse_lscpu():
    out = {}
    for line in read("/tmp/_cpu.txt").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out

def parse_lspci():
    return [line.strip() for line in read("/tmp/_pci.txt").splitlines() if line.strip()]

def parse_lsblk():
    try:
        with open("/tmp/_disk.json") as f: return json.load(f)
    except:
        return {"raw": read("/tmp/_disk.json")}

def parse_mem_free():
    lines = read("/tmp/_free.txt").splitlines()
    result = {}
    if len(lines) >= 2:
        headers = lines[0].split()
        for row in lines[1:]:
            parts = row.split()
            if parts:
                result[parts[0].rstrip(":")] = dict(zip(headers, parts[1:]))
    return result

def parse_dmidecode_sections(path):
    text = read(path)
    sections = []
    for block in re.split(r'\n\n+', text):
        if block.strip():
            obj = {}
            for line in block.splitlines():
                if ":" in line and not line.startswith("\t\t"):
                    k, _, v = line.partition(":")
                    obj[k.strip()] = v.strip()
            if obj:
                sections.append(obj)
    return sections

result = {
    "hostname": socket.gethostname(),
    "bios": parse_dmidecode_sections("/tmp/_bios.txt"),
    "cpu": parse_lscpu(),
    "pci": parse_lspci(),
    "disks": parse_lsblk(),
    "memory_slots": parse_dmidecode_sections("/tmp/_mem.txt"),
    "memory_free": parse_mem_free(),
    "network": read("/tmp/_net.txt"),
    "lshw": parse_lshw(),
}

print(json.dumps(result, indent=2))
PYEOF
}

OUTPUT_DIR="./inventory_results"
mkdir -p "$OUTPUT_DIR"

if [ "$REMOTE_MODE" = false ]; then
    HOSTNAME_SHORT=$(hostname)
    OUTPUT_FILE="${OUTPUT_DIR}/${HOSTNAME_SHORT}-hardware-component-inventory-results.json"
    collect_inventory > "$OUTPUT_FILE"
    echo "Saved: $OUTPUT_FILE"
else
    CONTROL_PATH="/tmp/ssh_ctrl_$$"

    cleanup() {
        ssh -o ControlPath="$CONTROL_PATH" -O exit "$TARGET" 2>/dev/null
        rm -f "$CONTROL_PATH"
    }
    trap cleanup EXIT

    ssh -M -f -N \
        -o ControlMaster=auto \
        -o ControlPath="$CONTROL_PATH" \
        -o ControlPersist=60 \
        "$TARGET"

    if [ $? -ne 0 ]; then
        echo "Failed to establish SSH master connection to $TARGET" >&2
        exit 1
    fi

    REMOTE_SCRIPT=$(declare -f collect_inventory)
    REMOTE_SCRIPT+=$'\n'
    REMOTE_SCRIPT+='echo "___HOSTNAME_MARKER___$(hostname)"'
    REMOTE_SCRIPT+=$'\n'
    REMOTE_SCRIPT+='collect_inventory'

    RAW_OUTPUT=$(ssh -o ControlPath="$CONTROL_PATH" "$TARGET" "bash -s" <<< "$REMOTE_SCRIPT")

    REMOTE_HOSTNAME=$(echo "$RAW_OUTPUT" | grep '___HOSTNAME_MARKER___' | sed 's/___HOSTNAME_MARKER___//')
    JSON_OUTPUT=$(echo "$RAW_OUTPUT" | grep -v '___HOSTNAME_MARKER___')

    OUTPUT_FILE="${OUTPUT_DIR}/${REMOTE_HOSTNAME}-hardware-component-inventory-results.json"
    echo "$JSON_OUTPUT" > "$OUTPUT_FILE"

    echo "Saved: $OUTPUT_FILE"
fi
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
sudo chmod +x hardware_component_inventory.sh
./hardware_component_inventory.sh # Local Inventory
./hardware_component_inventory.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
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
