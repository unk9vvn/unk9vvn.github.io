# Data Inventory

## Cheat Sheet

### Local & Remote Windows Data Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect Windows filesystem inventory data including hostname, asset type, file path, MIME type, owner, ACL permissions, file size, and last modification time
{% endhint %}

```powershell
<#
.SYNOPSIS
    Comprehensive Windows Data Inventory Script.

.DESCRIPTION
    Performs Windows filesystem Data Inventory for local and remote hosts.
    Discovers data-oriented files, extracts metadata and ACL information,
    and writes one JSON object per line in JSONL format for each host.

.EXAMPLE
    .\data-inventory.ps1

.EXAMPLE
    .\data-inventory.ps1 HOST-01,HOST-02,192.168.1.10

.OUTPUT
    inventory_results\<hostname>-data_inventory_results.jsonl
#>

param(
    [Parameter(Position = 0)]
    [string]$Targets
)

$OutputDir = "inventory_results"

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
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

$DataInventoryScriptBlock = {
    $ExcludeExtensions = @(
        ".pt", ".c", ".cpp", ".h", ".py", ".js", ".ts", ".java",
        ".go", ".rs", ".rb", ".php", ".sh", ".swift", ".kt",
        ".exe", ".dll", ".sys", ".msi"
    )

    $TargetExtensions = @(
        ".pdf", ".json", ".csv", ".txt", ".xml",
        ".zip", ".gz", ".doc", ".docx", ".xls", ".xlsx"
    )

    $PrunePaths = @(
        "C:\Windows",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData"
    )

    $MimeMap = @{
        ".pdf"  = "application/pdf"
        ".json" = "application/json"
        ".csv"  = "text/csv"
        ".txt"  = "text/plain"
        ".xml"  = "application/xml"
        ".zip"  = "application/zip"
        ".gz"   = "application/gzip"
        ".doc"  = "application/msword"
        ".docx" = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ".xls"  = "application/vnd.ms-excel"
        ".xlsx" = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }

    $Results = New-Object System.Collections.Generic.List[string]

    $Drives = Get-PSDrive -PSProvider FileSystem |
        Where-Object {
            $_.Root -and $_.Free -ne $null
        } |
        Select-Object -ExpandProperty Root

    foreach ($Drive in $Drives) {
        try {
            Get-ChildItem -Path $Drive -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $FilePath = $_.FullName
                    $Extension = $_.Extension.ToLowerInvariant()

                    $IsPrunedPath = $false
                    foreach ($PrunePath in $PrunePaths) {
                        if ($FilePath.StartsWith($PrunePath, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $IsPrunedPath = $true
                            break
                        }
                    }

                    if ($IsPrunedPath) {
                        return $false
                    }

                    if ($ExcludeExtensions -contains $Extension) {
                        return $false
                    }

                    if ($TargetExtensions -contains $Extension) {
                        return $true
                    }

                    return $false
                } |
                ForEach-Object {
                    try {
                        $File = $_
                        $Acl = Get-Acl -Path $File.FullName -ErrorAction Stop
                        $Extension = $File.Extension.ToLowerInvariant()
                        $MimeType = "application/octet-stream"

                        if ($MimeMap.ContainsKey($Extension)) {
                            $MimeType = $MimeMap[$Extension]
                        }

                        $InventoryItem = [PSCustomObject]@{
                            hostname             = $env:COMPUTERNAME
                            asset_type           = "filesystem"
                            location             = $File.FullName
                            mime_type            = $MimeType
                            owner                = $Acl.Owner
                            permissions_symbolic = ($Acl.AccessToString -replace "`r?`n", " | ")
                            size_bytes           = $File.Length
                            mtime                = $File.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }

                        [void]$Results.Add(($InventoryItem | ConvertTo-Json -Compress -Depth 5))
                    }
                    catch {
                        continue
                    }
                }
        }
        catch {
            continue
        }
    }

    return $Results
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $RawJsonLines = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $RawJsonLines = & $DataInventoryScriptBlock
        }
        else {
            $RawJsonLines = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $DataInventoryScriptBlock `
                -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[-] Current user context failed for $Target. Requesting credentials..." -ForegroundColor DarkGray
    }

    if ($null -eq $RawJsonLines -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target
            $RawJsonLines = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $DataInventoryScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $RawJsonLines -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local inventory from ${Target}." -ForegroundColor Red
        continue
    }

    $RawJsonLines = @($RawJsonLines)

    if ($RawJsonLines.Count -gt 0) {
        try {
            $FirstObject = $RawJsonLines[0] | ConvertFrom-Json -ErrorAction Stop
            if ($FirstObject.hostname) {
                $FinalHostName = $FirstObject.hostname
            }
        }
        catch {
            $FinalHostName = $Target
        }
    }
    else {
        Write-Host "[!] No records collected from ${Target}." -ForegroundColor Yellow
    }

    $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
    $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-data_inventory_results.jsonl"

    try {
        $RawJsonLines | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
        $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

        Write-Host "[+] Inventory saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
        Write-Host "[+] Total records collected: $($RawJsonLines.Count)" -ForegroundColor Gray
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
notepad data-inventory.ps1
.\data-inventory.ps1 # Local Inventory
.\data-inventory.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Linux Data Inventory

#### [find](https://www.man7.org/linux/man-pages/man1/find.1.html) & [jq](https://jqlang.org/)

{% hint style="info" %}
Collect document locations, types, owners, groups, permissions, sizes, and modification dates
{% endhint %}

```bash
#!/bin/bash

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local directory: $LOCAL_DIR" >&2
    exit 1
}

run_inventory_block() {
    inventory_hostname="$1"
    output_file="$2"

    echo "[+] Inventory command block started." >&2
    echo "[+] Inventory hostname: $inventory_hostname" >&2
    echo "[+] Writing inventory to: $output_file" >&2

    if ! : > "$output_file"; then
        echo "[ERROR] Cannot create output file: $output_file" >&2
        exit 10
    fi

    count=0
    matched=0

    echo "[*] Starting find scan from / ..." >&2

find / \
    \( \
        -path /proc -o -path '/proc/*' -o \
        -path /sys -o -path '/sys/*' -o \
        -path /dev -o -path '/dev/*' -o \
        -path /run -o -path '/run/*' -o \
        -path /snap -o -path '/snap/*' -o \
        -path /boot -o -path '/boot/*' -o \
        -path /bin -o -path '/bin/*' -o \
        -path /sbin -o -path '/sbin/*' -o \
        -path /lib -o -path '/lib/*' -o \
        -path /lib64 -o -path '/lib64/*' -o \
        -path /usr -o -path '/usr/*' -o \
        -path /etc -o -path '/etc/*' -o \
        -path /opt -o -path '/opt/*' -o \
        -path /var -o -path '/var/*' -o \
        -path /root -o -path '/root/*' -o \
        -path /srv -o -path '/srv/*' -o \
        -path /media -o -path '/media/*' -o \
        -path /mnt -o -path '/mnt/*' \
    \) -prune -o \
    \( \
        -type f \
        ! -executable \
        ! -regex '.*\.\(c\|cc\|cpp\|cxx\|h\|hpp\|hh\|py\|pyc\|pyo\|js\|mjs\|ts\|java\|class\|jar\|go\|rs\|rb\|php\|sh\|bash\|zsh\|ksh\|pl\|pm\|swift\|kt\|kts\|scala\|cs\|vb\|ps1\|psm1\|bat\|cmd\|sql\|html\|htm\|css\|xml\|yaml\|yml\|toml\|ini\|conf\)$' \
        -print0 \
    \) 2>/dev/null |
    while IFS= read -r -d '' file_path; do
        count=$((count + 1))

        if [ $((count % 1000)) -eq 0 ]; then
            echo "[*] find is running... files checked: $count, matched: $matched" >&2
        fi

        mime_type="$(
            file --mime-type -b "$file_path" 2>/dev/null ||
                true
        )"

        [ -z "$mime_type" ] && continue

        case "$mime_type" in
            application/pdf|\
            application/json|\
            text/csv|\
            text/plain|\
            application/xml|\
            text/xml|\
            application/zip|\
            application/gzip|\
            application/x-gzip|\
            application/vnd*|\
            application/octet-stream)

                owner="$(
                    stat -c '%U' "$file_path" 2>/dev/null ||
                        echo unknown
                )"

                group="$(
                    stat -c '%G' "$file_path" 2>/dev/null ||
                        echo unknown
                )"

                permissions_symbolic="$(
                    stat -c '%A' "$file_path" 2>/dev/null ||
                        echo unknown
                )"

                permissions_octal="$(
                    stat -c '%a' "$file_path" 2>/dev/null ||
                        echo 0
                )"

                size_bytes="$(
                    stat -c '%s' "$file_path" 2>/dev/null ||
                        echo 0
                )"

                mtime="$(
                    stat -c '%y' "$file_path" 2>/dev/null ||
                        echo unknown
                )"

                case "$size_bytes" in
                    ''|*[!0-9]*)
                        size_bytes=0
                        ;;
                esac

                if jq -nc \
                    --arg hostname "$inventory_hostname" \
                    --arg asset_type "filesystem" \
                    --arg location "$file_path" \
                    --arg mime_type "$mime_type" \
                    --arg owner "$owner" \
                    --arg group "$group" \
                    --arg permissions_symbolic "$permissions_symbolic" \
                    --arg permissions_octal "$permissions_octal" \
                    --arg mtime "$mtime" \
                    --argjson size_bytes "$size_bytes" \
                    '{
                        hostname: $hostname,
                        asset_type: $asset_type,
                        location: $location,
                        mime_type: $mime_type,
                        owner: $owner,
                        group: $group,
                        permissions_symbolic: $permissions_symbolic,
                        permissions_octal: $permissions_octal,
                        size_bytes: $size_bytes,
                        mtime: $mtime
                    }' >> "$output_file"
                then
                    matched=$((matched + 1))
                else
                    echo "[WARNING] jq failed for: $file_path" >&2
                fi
                ;;
        esac
    done

    if [ ! -f "$output_file" ]; then
        echo "[ERROR] Output file does not exist: $output_file" >&2
        exit 11
    fi

    record_count="$(
        wc -l < "$output_file" 2>/dev/null ||
            echo 0
    )"

    echo "[+] find scan completed." >&2
    echo "[+] Inventory records written: $record_count" >&2
    echo "[+] Inventory file: $output_file" >&2

    exit 0
}

check_dependencies() {
    missing=0

    for command_name in bash find file stat jq hostname wc sed tr mktemp; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing dependency: $command_name" >&2
            missing=1
        fi
    done

    return "$missing"
}

make_safe_hostname() {
    printf '%s' "$1" |
        tr -d '\r\n' |
        sed 's/[^A-Za-z0-9._-]/_/g'
}

if [ -z "$1" ]; then
    echo "[*] Running in local mode ..."
    echo "[*] Checking local dependencies ..."

    if ! check_dependencies; then
        echo "[ERROR] One or more required commands are not available on the local host." >&2
        echo "[INFO] On Debian or Ubuntu, install them with:" >&2
        echo "       sudo apt update && sudo apt install findutils file coreutils jq" >&2
        exit 1
    fi

    LOCAL_HOSTNAME="$(
        hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host
    )"

    LOCAL_HOSTNAME="$(
        printf '%s' "$LOCAL_HOSTNAME" |
            tr -d '\r\n'
    )"

    if [ -z "$LOCAL_HOSTNAME" ]; then
        echo "[ERROR] Local hostname is empty." >&2
        exit 1
    fi

    SAFE_HOSTNAME="$(make_safe_hostname "$LOCAL_HOSTNAME")"

    if [ -z "$SAFE_HOSTNAME" ]; then
        SAFE_HOSTNAME="unknown-host"
    fi

    LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-data-inventory.jsonl"

    echo "[+] Local hostname: $LOCAL_HOSTNAME"
    echo "[+] Local output file: $LOCAL_FILE"
    echo "[*] Starting local filesystem inventory ..."

    run_inventory_block "$LOCAL_HOSTNAME" "$LOCAL_FILE"
fi

TARGET="$1"

CONTROL_DIR="$(mktemp -d)" || {
    echo "[ERROR] Failed to create temporary SSH control directory." >&2
    exit 1
}

CONTROL_PATH="$CONTROL_DIR/ssh-control-%r@%h:%p"

SSH_OPTS=(
    -o ControlMaster=auto
    -o ControlPath="$CONTROL_PATH"
    -o ControlPersist=10m
)

cleanup_ssh_control() {
    ssh "${SSH_OPTS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
    rm -rf "$CONTROL_DIR"
}

trap cleanup_ssh_control EXIT

echo "[*] Running in remote mode ..."
echo "[*] Testing SSH connection to $TARGET ..."

if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 "$TARGET" \
    'echo "[+] SSH connection established on: $(hostname)"'
then
    echo "[ERROR] SSH connection failed: $TARGET" >&2
    exit 1
fi

echo "[*] Checking remote dependencies ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" '
    missing=0

    for command_name in bash find file stat jq hostname wc sed tr mktemp; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing remote dependency: $command_name" >&2
            missing=1
        fi
    done

    exit "$missing"
'
then
    echo "[ERROR] One or more required commands are not available on the remote host." >&2
    echo "[INFO] On Debian or Ubuntu, install them with:" >&2
    echo "       sudo apt update && sudo apt install findutils file coreutils jq" >&2
    exit 1
fi

echo "[*] Getting remote hostname ..."

REMOTE_HOSTNAME="$(
    ssh "${SSH_OPTS[@]}" "$TARGET" \
        'hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown-host'
)"
HOSTNAME_EXIT=$?

if [ "$HOSTNAME_EXIT" -ne 0 ]; then
    echo "[ERROR] Failed to retrieve the remote hostname." >&2
    exit 1
fi

REMOTE_HOSTNAME="$(
    printf '%s' "$REMOTE_HOSTNAME" |
        tr -d '\r\n'
)"

if [ -z "$REMOTE_HOSTNAME" ]; then
    echo "[ERROR] Remote hostname is empty." >&2
    exit 1
fi

SAFE_HOSTNAME="$(make_safe_hostname "$REMOTE_HOSTNAME")"

if [ -z "$SAFE_HOSTNAME" ]; then
    SAFE_HOSTNAME="unknown-host"
fi

REMOTE_FILE="/tmp/${SAFE_HOSTNAME}-data-inventory.jsonl"
LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-data-inventory.jsonl"

echo "[+] Remote hostname: $REMOTE_HOSTNAME"
echo "[+] Remote output file: $REMOTE_FILE"
echo "[+] Local output file: $LOCAL_FILE"
echo "[*] Starting remote filesystem inventory ..."

{
    declare -f run_inventory_block
    printf 'run_inventory_block "$1" "$2"\n'
} | ssh "${SSH_OPTS[@]}" "$TARGET" bash -s -- "$REMOTE_HOSTNAME" "$REMOTE_FILE"

SSH_EXIT=$?

if [ "$SSH_EXIT" -ne 0 ]; then
    echo "[ERROR] Remote inventory command failed." >&2
    echo "[ERROR] SSH exit code: $SSH_EXIT" >&2
    echo "[INFO] The script will not continue to scp." >&2
    exit 1
fi

echo "[+] Remote inventory command completed successfully."
echo "[*] Verifying remote inventory file ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" "test -s '$REMOTE_FILE'"; then
    echo "[ERROR] Remote inventory file is missing or empty: $REMOTE_FILE" >&2
    exit 1
fi

echo "[*] Retrieving ${SAFE_HOSTNAME}-data-inventory.jsonl ..."

if ! scp "${SSH_OPTS[@]}" -- "$TARGET:$REMOTE_FILE" "$LOCAL_FILE"; then
    echo "[ERROR] scp failed while retrieving: $REMOTE_FILE" >&2
    exit 1
fi

if [ ! -s "$LOCAL_FILE" ]; then
    echo "[ERROR] Retrieved file is empty or missing: $LOCAL_FILE" >&2
    exit 1
fi

LOCAL_RECORD_COUNT="$(
    wc -l < "$LOCAL_FILE" 2>/dev/null ||
        echo 0
)"

echo "[+] Inventory file retrieved successfully."
echo "[+] Local inventory records: $LOCAL_RECORD_COUNT"

echo "[*] Cleaning up remote inventory file ..."

if ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f -- '$REMOTE_FILE'"; then
    echo "[+] Remote inventory file removed."
else
    echo "[WARNING] Could not remove remote file: $REMOTE_FILE" >&2
fi

echo "[+] Inventory complete."
echo "[+] Saved to: $LOCAL_FILE"
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
sudo chmod +x data-inventory.sh
sudo ./data-inventory.sh # Local Inventory
sudo ./data-inventory.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```
