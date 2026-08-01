# Software Inventory

## Cheat Sheet

### Windows Local Software Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
List all installed softwares, services and running processes
{% endhint %}

```ps1
function Get-SystemInventory {
    $softwarePaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $software = Get-ItemProperty -Path $softwarePaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName

    $services = Get-Service |
        Select-Object Name,
                      DisplayName,
                      @{Name="Status"; Expression={$_.Status.ToString()}},
                      @{Name="StartType"; Expression={$_.StartType.ToString()}}

    $processes = Get-Process |
        Select-Object ProcessName, Id, Path

    [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Hostname  = $env:COMPUTERNAME
        Software  = $software
        Services  = $services
        Processes = $processes
    }
}

$outputDirectory = 'C:\Software Inventory'

if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

$results = Get-SystemInventory
$outputPath = Join-Path -Path $outputDirectory -ChildPath "$env:COMPUTERNAME-software-inventory.json"

$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "Inventory completed. Saved to $outputPath"
```

{% hint style="info" %}
Save & Execute (Run as administrator)
{% endhint %}

```powershell
notepad .\local-software-inventory.ps1
.\local-software-inventory.ps1
```

### Windows Remote Software Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
List all installed softwares, services and running processes
{% endhint %}

```ps1
$ComputerNameInput = Read-Host "Enter computer names separated by comma (e.g., HOST-01,HOST-02)"
$OutputDirectory = 'C:\Software Inventory'

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory | Out-Null
}

$ComputerName = @(
    $ComputerNameInput -split ',' |
        ForEach-Object { $_.Trim().Replace("`r", "").Replace("`n", "") } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
)

function Read-CliCredentialForTarget {
    param([string]$Target)
    Write-Host "Credentials required for $Target" -ForegroundColor Yellow
    $UserName = Read-Host "Username for $Target (Format: DOMAIN\User or $Target\User)"
    $Password = Read-Host "Password for $Target" -AsSecureString
    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

$SoftwareInventoryScript = {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Windows\CurrentVersion\Uninstall\*'
    )

    $software = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object DisplayName

    $services = Get-Service |
        Select-Object Name, DisplayName, Status, StartType |
        Sort-Object Name

    $processes = Get-Process -ErrorAction SilentlyContinue |
        Select-Object ProcessName, Id, Path |
        Sort-Object ProcessName

    [pscustomobject]@{
        Hostname       = $env:COMPUTERNAME
        CollectionTime = (Get-Date).ToString('o')
        SoftwareCount  = @($software).Count
        ServiceCount   = @($services).Count
        ProcessCount   = @($processes).Count
        Software       = @($software)
        Services       = @($services)
        Processes      = @($processes)
    }
}

foreach ($Target in $ComputerName) {
    Write-Host "`nProcessing: $Target" -ForegroundColor Cyan
    $result = $null

    try {
        $result = Invoke-Command -ComputerName $Target -ScriptBlock $SoftwareInventoryScript -ErrorAction Stop
    }
    catch {
        Write-Host "Current user context failed for $Target" -ForegroundColor DarkGray
    }

    if ($null -eq $result) {
        try {
            $cred = Read-CliCredentialForTarget -Target $Target
            $result = Invoke-Command -ComputerName $Target -ScriptBlock $SoftwareInventoryScript -Credential $cred -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to collect from $Target : $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -ne $result) {
        $outputPath = Join-Path -Path $OutputDirectory -ChildPath "$($result.Hostname)-software-inventory.json"
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Encoding UTF8
        Write-Host "Inventory saved: $outputPath" -ForegroundColor Green
    }
}
```

{% hint style="info" %}
Save & Execute (Run as administrator)
{% endhint %}

```powershell
notepad .\remote-software-inventory.ps1
.\remote-software-inventory.ps1
```

### Linux Local Software Inventory

#### Ubuntu/Debian-based

{% hint style="info" %}
Gather OS, kernel, installed packages and systemd services Information
{% endhint %}

```bash
mkdir -p software_inventory

{
    echo "=== OS INFO ==="
    cat /etc/os-release

    echo -e "\n\n=== KERNEL ==="
    uname -a

    echo -e "\n\n=== DPKG PACKAGES ==="
    COLUMNS=1000 dpkg -l

    echo -e "\n\n=== SNAP PACKAGES ==="
    command -v snap >/dev/null 2>&1 && snap list || echo "snap not installed"

    echo -e "\n\n=== FLATPAK PACKAGES ==="
    command -v flatpak >/dev/null 2>&1 && flatpak list || echo "flatpak not installed"

    echo -e "\n\n=== SYSTEMD SERVICES ==="
    systemctl list-unit-files --type=service
} > "software_inventory/$(hostname)-software-inventory.txt"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x local-debian-software-inventory.sh
./local-debian-software-inventory.sh
```

#### RPM-based

{% hint style="info" %}
Gather OS, kernel, installed packages and systemd services Information
{% endhint %}

```bash
mkdir -p software_inventory

{
    echo "=== OS INFO ==="
    cat /etc/os-release

    echo -e "\n\n=== KERNEL ==="
    uname -a

    echo -e "\n\n=== RPM PACKAGES ==="
    rpm -qa | sort

    echo -e "\n\n=== SNAP PACKAGES ==="
    command -v snap >/dev/null 2>&1 && snap list || echo "snap not installed"

    echo -e "\n\n=== FLATPAK PACKAGES ==="
    command -v flatpak >/dev/null 2>&1 && flatpak list || echo "flatpak not installed"

    echo -e "\n\n=== SYSTEMD SERVICES ==="
    systemctl list-unit-files --type=service
} > "software_inventory/$(hostname)-software-inventory.txt"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x local-rpm-software-inventory.sh
./local-rpm-software-inventory.sh
```

### Linux Remote Software Inventory (SSH)

#### Ubuntu/Debian-based

{% hint style="info" %}
Gather OS, kernel, installed packages and systemd services Information
{% endhint %}

```bash
#!/bin/bash

# Usage check
if [ -z "$1" ]; then
    echo "Usage: $0 <user@remote-target-ip>"
    echo "Example: $0 ubuntu@192.168.109.150"
    exit 1
fi

# Configuration
TARGET="$1"
LOCAL_DIR="./software_inventory"
mkdir -p "$LOCAL_DIR"

echo "Connecting to $TARGET to perform Debian/Ubuntu software inventory..."

# Execute command block remotely.
# The inventory file is created on the remote host using its hostname.
ssh "$TARGET" '
    REMOTE_HOSTNAME=$(hostname)
    FILE_NAME="${REMOTE_HOSTNAME}-software-inventory.txt"

    (
        echo "=== OS INFO ==="
        cat /etc/os-release

        echo -e "\n\n=== KERNEL ==="
        uname -a

        echo -e "\n\n=== DPKG PACKAGES ==="
        COLUMNS=1000 dpkg -l

        echo -e "\n\n=== SNAP PACKAGES ==="
        command -v snap >/dev/null 2>&1 && snap list || echo "snap not installed"

        echo -e "\n\n=== FLATPAK PACKAGES ==="
        command -v flatpak >/dev/null 2>&1 && flatpak list || echo "flatpak not installed"

        echo -e "\n\n=== SYSTEMD SERVICES ==="
        systemctl list-unit-files --type=service
    ) > "$FILE_NAME"
'

# Extract the hostname from the remote machine to verify the filename for SCP
REMOTE_HOST_NAME=$(ssh "$TARGET" "hostname")
REMOTE_FILE="${REMOTE_HOST_NAME}-software-inventory.txt"

# Retrieve the file
echo "Retrieving $REMOTE_FILE..."
scp "$TARGET:$REMOTE_FILE" "$LOCAL_DIR/"

# Verify local output file
if [ ! -s "$LOCAL_DIR/$REMOTE_FILE" ]; then
    echo "Error: inventory file was not retrieved or is empty: $LOCAL_DIR/$REMOTE_FILE"
    exit 1
fi

# Cleanup: Remove file from remote host
echo "Cleaning up remote host..."
ssh "$TARGET" "rm -f '$REMOTE_FILE'"

echo "Inventory complete. Saved to: $LOCAL_DIR/$REMOTE_FILE"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x remote-debian-software-inventory.sh
./remote-debian-software-inventory.sh username@1.2.3.4
```

#### RPM-based

{% hint style="info" %}
Gather OS, kernel, installed packages and systemd services Information
{% endhint %}

```bash
#!/bin/bash

# Usage check
if [ -z "$1" ]; then
    echo "Usage: $0 <user@remote-target-ip>"
    echo "Example: $0 rocky@192.168.109.160"
    exit 1
fi

# Configuration
TARGET="$1"
LOCAL_DIR="./software_inventory"
mkdir -p "$LOCAL_DIR"

echo "Connecting to $TARGET to perform RPM-based software inventory..."

# Execute command block remotely.
# The inventory file is created on the remote host using its hostname.
ssh "$TARGET" '
    REMOTE_HOSTNAME=$(hostname)
    FILE_NAME="${REMOTE_HOSTNAME}-software-inventory.txt"

    (
        echo "=== OS INFO ==="
        cat /etc/os-release

        echo -e "\n\n=== KERNEL ==="
        uname -a

        echo -e "\n\n=== RPM PACKAGES ==="
        rpm -qa | sort

        echo -e "\n\n=== SNAP PACKAGES ==="
        command -v snap >/dev/null 2>&1 && snap list || echo "snap not installed"

        echo -e "\n\n=== FLATPAK PACKAGES ==="
        command -v flatpak >/dev/null 2>&1 && flatpak list || echo "flatpak not installed"

        echo -e "\n\n=== SYSTEMD SERVICES ==="
        systemctl list-unit-files --type=service
    ) > "$FILE_NAME"
'

# Extract the hostname from the remote machine to verify the filename for SCP
REMOTE_HOST_NAME=$(ssh "$TARGET" "hostname")
REMOTE_FILE="${REMOTE_HOST_NAME}-software-inventory.txt"

# Retrieve the file
echo "Retrieving $REMOTE_FILE..."
scp "$TARGET:$REMOTE_FILE" "$LOCAL_DIR/"

# Verify local output file
if [ ! -s "$LOCAL_DIR/$REMOTE_FILE" ]; then
    echo "Error: inventory file was not retrieved or is empty: $LOCAL_DIR/$REMOTE_FILE"
    exit 1
fi

# Cleanup: Remove file from remote host
echo "Cleaning up remote host..."
ssh "$TARGET" "rm -f '$REMOTE_FILE'"

echo "Inventory complete. Saved to: $LOCAL_DIR/$REMOTE_FILE"
```

{% hint style="info" %}
Save & Execute (Run with sudo)
{% endhint %}

```bash
sudo chmod +x remote-rpm-software-inventory.sh
./remote-rpm-software-inventory.sh username@1.2.3.4
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
