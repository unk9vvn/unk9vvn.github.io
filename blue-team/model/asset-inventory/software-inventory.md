# Software Inventory

## Cheat Sheet

### Local & Remote Linux Software Inventory

#### [uname](https://man7.org/linux/man-pages/man1/uname.1.html) & [dpkg-query](https://man7.org/linux/man-pages/man1/dpkg-query.1.html) & [rpm](https://rpm.org/) & [snap](https://snapcraft.io/) & [flatpak](https://flatpak.org/)

{% hint style="info" %}
Collect host metadata, operating system details, kernel version, and lists of installed packages from DPKG, RPM, Snap, and Flatpak managers.
{% endhint %}

```bash
#!/bin/bash

# Configuration
LOCAL_DIR="./inventory_results"
mkdir -p "$LOCAL_DIR" || { echo "[ERROR] Failed to create $LOCAL_DIR"; exit 1; }

# --- Function: Inventory Logic (Executed Local or Remote) ---
run_software_inventory() {
    local inv_hostname="$1"
    local output_file="$2"

    echo "[*] Collecting software info for: $inv_hostname" >&2

    {
        echo "{"
        echo "  \"hostname\": \"$inv_hostname\","
        echo "  \"collection_time\": \"$(date -Iseconds)\","
        
        # OS and Kernel Info
        echo "  \"os_info\": $([ -f /etc/os-release ] && cat /etc/os-release | grep -E '^(ID|VERSION_ID)=' | sed 's/ID=//' | tr -d '"' | jq -R . | jq -s '.[0:2]' || echo "null"),"
        echo "  \"kernel\": \"$(uname -r)\","

        # Detect Package Manager and Collect with Descriptions
        if command -v dpkg >/dev/null 2>&1; then
            echo "  \"package_manager\": \"dpkg\","
            echo "  \"installed_packages\": ["
            dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Binary:Summary}\n' | while IFS=$'\t' read -r pkg ver arch desc; do
                # Double check if variables are not empty to prevent JSON corruption
                [[ -z "$pkg" ]] && continue
                jq -nc --arg name "$pkg" --arg version "$ver" --arg arch "$arch" --arg description "$desc" \
                   '{name: $name, version: $version, arch: $arch, description: $description}'
            done | sed 's/$/,/' | sed '$ s/,$//'
            echo "  ],"
        elif command -v rpm >/dev/null 2>&1; then
            echo "  \"package_manager\": \"rpm\","
            echo "  \"installed_packages\": ["
            rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n' | while IFS=$'\t' read -r pkg ver arch desc; do
                [[ -z "$pkg" ]] && continue
                jq -nc --arg name "$pkg" --arg version "$ver" --arg arch "$arch" --arg description "$desc" \
                   '{name: $name, version: $version, arch: $arch, description: $description}'
            done | sed 's/$/,/' | sed '$ s/,$//'
            echo "  ],"
        fi

        # Snap Packages (Handling old versions without --json)
        echo "  \"snap_packages\": "
        if command -v snap >/dev/null 2>&1; then
            if snap list --json >/dev/null 2>&1; then
                snap list --json | jq '.'
            else
                # Fallback for old snap versions
                snap list | tail -n +2 | awk '{print $1,$2,$3,$4}' | while read -r sname sver srev schan; do
                    jq -nc --arg n "$sname" --arg v "$sver" --arg r "$srev" --arg c "$schan" '{name: $n, version: $v, rev: $r, channel: $c}'
                done | jq -s '.'
            fi
        else
            echo "[]"
        fi
        echo ","
        
        # Flatpak Packages
        echo "  \"flatpak_packages\": ["
        if command -v flatpak >/dev/null 2>&1; then
             flatpak list --columns=name,application,version,description --parsable | while IFS=$'\t' read -r name id ver desc; do
                jq -nc --arg n "$name" --arg i "$id" --arg v "$ver" --arg d "$desc" \
                   '{name: $n, id: $i, version: $v, description: $d}'
             done | sed 's/$/,/' | sed '$ s/,$//'
        fi
        echo "  ]"
        echo "}"
    } | jq '.' > "$output_file"

    if [ -s "$output_file" ]; then
        echo "[+] Inventory written to: $output_file" >&2
        return 0
    else
        return 1
    fi
}

# --- Helper Functions ---
check_deps() {
    for cmd in jq hostname sed awk tr; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[ERROR] Missing local dependency: $cmd" >&2
            return 1
        fi
    done
}

make_safe_name() {
    printf '%s' "$1" | tr -d '\r\n' | sed 's/[^A-Za-z0-9._-]/_/g'
}

# --- Main Logic ---
if [ -z "$1" ]; then
    check_deps || exit 1
    L_HOST="$(hostname -s)"
    SAFE_H="$(make_safe_name "$L_HOST")"
    L_FILE="${LOCAL_DIR}/${SAFE_H}-software-inventory.json"
    run_software_inventory "$L_HOST" "$L_FILE"
    exit 0
fi

TARGET="$1"
CONTROL_DIR="$(mktemp -d)"
CONTROL_PATH="$CONTROL_DIR/ssh_sock"

cleanup() {
    ssh -S "$CONTROL_PATH" -O exit "$TARGET" >/dev/null 2>&1
    rm -rf "$CONTROL_DIR"
}
trap cleanup EXIT

echo "[*] Establishing stable SSH connection to $TARGET..."
if ! ssh -o ControlMaster=yes -o ControlPath="$CONTROL_PATH" -o ControlPersist=10m "$TARGET" "true"; then
    echo "[ERROR] Could not authenticate or connect to $TARGET"
    exit 1
fi

if ! ssh -S "$CONTROL_PATH" "$TARGET" 'command -v jq >/dev/null 2>&1'; then
    echo "[ERROR] 'jq' is not installed on remote host ($TARGET)."
    exit 1
fi

R_HOST="$(ssh -S "$CONTROL_PATH" "$TARGET" 'hostname -s')"
SAFE_H="$(make_safe_name "$R_HOST")"
R_FILE="/tmp/${SAFE_H}-software-raw.json"
L_FILE="${LOCAL_DIR}/${SAFE_H}-software-inventory.json"

echo "[*] Running remote inventory..."
{
    declare -f run_software_inventory
    echo 'run_software_inventory "$1" "$2"'
} | ssh -S "$CONTROL_PATH" "$TARGET" bash -s -- "$R_HOST" "$R_FILE"

if [ $? -eq 0 ]; then
    scp -o ControlPath="$CONTROL_PATH" "$TARGET:$R_FILE" "$L_FILE"
    ssh -S "$CONTROL_PATH" "$TARGET" "rm -f '$R_FILE'"
    echo "[DONE] Inventory saved to: $L_FILE"
else
    echo "[ERROR] Remote execution failed."
    exit 1
fi
```

Save & Execute

```bash
sudo chmod +x software_inventory.sh
./software_inventory.sh # Local Inventory
./software_inventory.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

### Local & Remote Windows Software Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
List all installed softwares
{% endhint %}

```powershell
<#
.SYNOPSIS
    Comprehensive Windows Software Inventory Script.

.DESCRIPTION
    Performs Windows software inventory (Installed Software) for local and remote hosts.
    Supports single or multiple targets via comma-separated strings or arrays.
    Outputs a consolidated JSON document for each target.

.EXAMPLE
    .\software-inventory.ps1

.EXAMPLE
    .\software-inventory.ps1 "HOST-01,HOST-02"

.EXAMPLE
    .\software-inventory.ps1 -Targets unk9vvn,WIN-E31P99E3C3J

.OUTPUT
    inventory_results\<hostname>-software-inventory.json
#>

param(
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [object]$Targets # Changed to object to handle both string and string[]
)

$OutputDir = "inventory_results"

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

# Normalize $Targets into a reliable string array ($ComputerNames)
$ComputerNames = @()
if ($null -eq $Targets -or ([string]::IsNullOrWhiteSpace($Targets.ToString()))) {
    $ComputerNames = @("localhost")
}
else {
    # Handle both direct array input and comma-separated string input
    $TargetList = if ($Targets -is [array]) { $Targets } else { $Targets -split ',' }
    
    $ComputerNames = $TargetList | ForEach-Object {
        $_.ToString().Trim().Replace("`r", "").Replace("`n", "")
    } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } | Select-Object -Unique
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

    Write-Host "`n[!] Credentials required for ${Target}" -ForegroundColor Yellow
    $UserName = Read-Host "Username for ${Target} (Format: DOMAIN\User or Administrator)"
    $Password = Read-Host "Password for ${Target}" -AsSecureString

    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

function Test-LocalTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $NormalizedTarget = $Target.Trim().ToLower()
    $LocalComputerName = $env:COMPUTERNAME.ToLower()

    if ($NormalizedTarget -eq "localhost" -or $NormalizedTarget -eq "." -or $NormalizedTarget -eq $LocalComputerName) {
        return $true
    }

    return $false
}

$SoftwareInventoryScriptBlock = {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $software = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName

    [pscustomobject]@{
        Hostname       = $env:COMPUTERNAME
        CollectionTime = (Get-Date).ToString('o')
        SoftwareCount  = @($software).Count
        Software       = @($software)
    }
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: ${Target}" -ForegroundColor Cyan

    $InventoryResult = $null
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $InventoryResult = & $SoftwareInventoryScriptBlock
        }
        else {
            $InventoryResult = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $SoftwareInventoryScriptBlock `
                -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[-] Current user context failed for ${Target}. Requesting credentials..." -ForegroundColor DarkGray
    }

    # Credential Fallback for Remote Hosts
    if ($null -eq $InventoryResult -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target
            $InventoryResult = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $SoftwareInventoryScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $InventoryResult -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local inventory from ${Target}." -ForegroundColor Red
        continue
    }

    if ($null -ne $InventoryResult) {
        # Extract Hostname from result (Remote execution returns a Deserialized object)
        $FinalHostName = $Target
        if ($InventoryResult.PSObject.Properties['Hostname']) {
            $FinalHostName = $InventoryResult.Hostname
        }

        # Safe filename cleanup
        $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
        $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-software-inventory.json"

        try {
            $InventoryResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
            $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

            Write-Host "[+] Inventory saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
            Write-Host "[+] Total software installed: $($InventoryResult.SoftwareCount)" -ForegroundColor Gray
        }
        catch {
            Write-Host "[!] Failed to write output for ${FinalHostName}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }
}

Write-Host "`n[*] All tasks completed." -ForegroundColor White
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
notepad software-inventory.ps1
.\software-inventory.ps1 # Local Inventory
.\software-inventory.ps1 # Remote Inventory via WinRM
```

### Cisco Products

#### Image information

```
show boot
```

#### Running Config

```
show running-config
```

#### Startup Config

```
show startup-config
```
