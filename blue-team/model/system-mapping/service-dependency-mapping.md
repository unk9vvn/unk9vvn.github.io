# Service Dependency Mapping

## Check List

* [ ] Identify critical services and their service consumers.
* [ ] Document intended dependencies using architecture artifacts and SME input.
* [ ] Discover runtime dependencies through logs, telemetry, and distributed tracing.
* [ ] Map service-to-service protocols, ports, endpoints, and authentication methods.
* [ ] Record upstream, downstream, synchronous, and asynchronous dependencies.
* [ ] Validate discovered dependencies against approved architecture and service ownership.
* [ ] Prioritize dependencies supporting critical organizational activities.\
  Assess third-party, cloud, SaaS, and supply-chain service dependencies.
* [ ] Identify undocumented, unnecessary, obsolete, or single-point-of-failure dependencies.
* [ ] Maintain and periodically update the dependency map after service changes.

## Cheat Sheet

### Local & Remote Windows Service Dependency Mapping

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect Windows service status, configuration, process ID, executable path and service dependency tree information
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows Service Dependency Mapping Inventory Script.

.DESCRIPTION
    Collects Windows service status information and service dependency trees
    for local and remote hosts.

    For each service, the script collects:
    - Name
    - DisplayName
    - State
    - StartMode
    - StartName
    - PathName
    - PID / ProcessId
    - Service dependency tree

.EXAMPLE
    .\service-dependency-mapping.ps1

.EXAMPLE
    .\service-dependency-mapping.ps1 unk9vvn,WIN-E31P99E3C3J

.EXAMPLE
    .\service-dependency-mapping.ps1 unk9vvn WIN-E31P99E3C3J

.EXAMPLE
    .\service-dependency-mapping.ps1 "unk9vvn,WIN-E31P99E3C3J"

.OUTPUT
    inventory_results\<hostname>-service-dependency-mapping-results.json
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

$ServiceDependencyMappingScriptBlock = {
    function Get-ServiceDependencyTreeObject {
        param (
            [Parameter(Mandatory = $true)]
            [string]$ServiceName,

            [int]$Level = 0,

            [hashtable]$Visited = @{}
        )

        try {
            $Service = Get-Service -Name $ServiceName -ErrorAction Stop
        }
        catch {
            return [PSCustomObject]@{
                name         = $ServiceName
                display_name = $null
                status       = "Not Found"
                level        = $Level
                already_seen = $false
                dependencies = @()
            }
        }

        if ($Visited.ContainsKey($ServiceName)) {
            return [PSCustomObject]@{
                name         = $Service.Name
                display_name = $Service.DisplayName
                status       = $Service.Status.ToString()
                level        = $Level
                already_seen = $true
                dependencies = @()
            }
        }

        $Visited[$ServiceName] = $true

        $DependencyObjects = @()

        foreach ($Dependency in ($Service.ServicesDependedOn | Sort-Object Name)) {
            $DependencyObjects += Get-ServiceDependencyTreeObject `
                -ServiceName $Dependency.Name `
                -Level ($Level + 1) `
                -Visited $Visited
        }

        return [PSCustomObject]@{
            name         = $Service.Name
            display_name = $Service.DisplayName
            status       = $Service.Status.ToString()
            level        = $Level
            already_seen = $false
            dependencies = $DependencyObjects
        }
    }

    function Show-ServiceDependencyTree {
        param (
            [string]$ServiceName,
            [int]$Level = 0,
            [hashtable]$Visited = @{}
        )

        $indent = "  " * $Level

        try {
            $service = Get-Service -Name $ServiceName -ErrorAction Stop
        }
        catch {
            Write-Output "$indent- $ServiceName [Not Found]"
            return
        }

        if ($Visited.ContainsKey($ServiceName)) {
            Write-Output "$indent- $ServiceName [Already Listed]"
            return
        }

        $Visited[$ServiceName] = $true

        Write-Output "$indent- $($service.Name) [$($service.Status)]"

        foreach ($dep in ($service.ServicesDependedOn | Sort-Object Name)) {
            Show-ServiceDependencyTree `
                -ServiceName $dep.Name `
                -Level ($Level + 1) `
                -Visited $Visited
        }
    }

    $HostName = $env:COMPUTERNAME

    $ServiceStatus = Get-CimInstance Win32_Service |
        Select-Object `
            Name,
            DisplayName,
            State,
            StartMode,
            StartName,
            PathName,
            @{
                Name = "PID"
                Expression = {
                    $_.ProcessId
                }
            }

    $ServiceDependencyResults = @()

    foreach ($Service in ($ServiceStatus | Sort-Object Name)) {
        $VisitedForObjectTree = @{}
        $VisitedForTextTree = @{}

        $DependencyTreeObject = Get-ServiceDependencyTreeObject `
            -ServiceName $Service.Name `
            -Level 0 `
            -Visited $VisitedForObjectTree

        $DependencyTreeText = Show-ServiceDependencyTree `
            -ServiceName $Service.Name `
            -Level 0 `
            -Visited $VisitedForTextTree

        $ServiceDependencyResults += [PSCustomObject]@{
            hostname             = $HostName
            asset_type           = "windows_service"
            name                 = $Service.Name
            display_name         = $Service.DisplayName
            state                = $Service.State
            start_mode           = $Service.StartMode
            start_name           = $Service.StartName
            path_name            = $Service.PathName
            pid                  = $Service.PID
            dependency_tree      = $DependencyTreeObject
            dependency_tree_text = @($DependencyTreeText)
        }
    }

    return [PSCustomObject]@{
        hostname      = $HostName
        collected_at  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        asset_type    = "windows_service_dependency_mapping"
        service_count = $ServiceDependencyResults.Count
        services      = $ServiceDependencyResults
    }
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $ResultObject = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $ResultObject = & $ServiceDependencyMappingScriptBlock
        }
        else {
            $ResultObject = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $ServiceDependencyMappingScriptBlock `
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
                -ScriptBlock $ServiceDependencyMappingScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $ResultObject -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local service dependency mapping from ${Target}." -ForegroundColor Red
        continue
    }

    if ($ResultObject.hostname) {
        $FinalHostName = $ResultObject.hostname
    }

    $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
    $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-service-dependency-mapping-results.json"

    try {
        $ResultObject |
            ConvertTo-Json -Depth 30 |
            Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force

        $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

        Write-Host "[+] Service dependency mapping saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
        Write-Host "[+] Total services collected: $($ResultObject.service_count)" -ForegroundColor Gray
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
notepad service-dependency-mapping.ps1
.\service-dependency-mapping.ps1 # Local Inventory
.\service-dependency-mapping.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Linux Service Dependency Mapping

#### [systemctl](https://man7.org/linux/man-pages/man1/systemctl.1.html) & [ps](https://man7.org/linux/man-pages/man1/ps.1.html)

{% hint style="info" %}
Collect Linux systemd service inventory, service dependency metadata, and running process information
{% endhint %}

```bash
#!/bin/bash

set -o pipefail

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local directory: $LOCAL_DIR" >&2
    exit 1
}

check_dependencies() {
    missing=0

    for command_name in bash systemctl ps jq hostname awk sed sort tr mktemp date; do
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

collect_service_inventory() {
    services_tmp="$1"

    unit_list_tmp="$(mktemp)" || {
        echo "[ERROR] Failed to create temporary unit list file." >&2
        return 1
    }

    : > "$unit_list_tmp"

    systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
        awk '{print $1}' |
        sed '/^[[:space:]]*$/d' |
        sort -u > "$unit_list_tmp"

    if [ ! -s "$unit_list_tmp" ]; then
        systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null |
            awk '{print $1}' |
            sed '/^[[:space:]]*$/d' |
            sort -u > "$unit_list_tmp"
    fi

    if [ ! -s "$unit_list_tmp" ]; then
        echo "[]" > "$services_tmp"
        rm -f "$unit_list_tmp"
        return 0
    fi

    while IFS= read -r unit_name; do
        [ -z "$unit_name" ] && continue

        systemctl show "$unit_name" \
            --no-pager \
            --property=Id \
            --property=Names \
            --property=Description \
            --property=LoadState \
            --property=ActiveState \
            --property=SubState \
            --property=UnitFileState \
            --property=FragmentPath \
            --property=SourcePath \
            --property=MainPID \
            --property=ExecMainPID \
            --property=User \
            --property=Group \
            --property=Type \
            --property=Restart \
            --property=ExecStart \
            --property=ExecStop \
            --property=Requires \
            --property=Wants \
            --property=After \
            --property=Before \
            --property=Conflicts \
            --property=PartOf \
            --property=WantedBy \
            2>/dev/null |
        jq -R -s '
            def split_words:
                if . == null or . == "" then
                    []
                else
                    split(" ") | map(select(. != ""))
                end;

            split("\n")
            | map(select(length > 0))
            | reduce .[] as $line (
                {};
                ($line | capture("^(?<key>[^=]+)=(?<value>.*)$")?) as $item
                | if $item == null then
                    .
                  else
                    .[$item.key] = $item.value
                  end
            )
            | select(.Id != null and .Id != "")
            | {
                unit: (.Id // ""),
                names: ((.Names // "") | split_words),
                description: (.Description // ""),
                load_state: (.LoadState // ""),
                active_state: (.ActiveState // ""),
                sub_state: (.SubState // ""),
                unit_file_state: (.UnitFileState // ""),
                fragment_path: (.FragmentPath // ""),
                source_path: (.SourcePath // ""),
                main_pid: ((.MainPID // "0") | tonumber? // 0),
                exec_main_pid: ((.ExecMainPID // "0") | tonumber? // 0),
                user: (.User // ""),
                group: (.Group // ""),
                type: (.Type // ""),
                restart: (.Restart // ""),
                exec_start: (.ExecStart // ""),
                exec_stop: (.ExecStop // ""),
                dependencies: {
                    requires: ((.Requires // "") | split_words),
                    wants: ((.Wants // "") | split_words),
                    after: ((.After // "") | split_words),
                    before: ((.Before // "") | split_words),
                    conflicts: ((.Conflicts // "") | split_words),
                    part_of: ((.PartOf // "") | split_words),
                    wanted_by: ((.WantedBy // "") | split_words)
                }
            }
        '
    done < "$unit_list_tmp" | jq -s '.' > "$services_tmp"

    collection_status=$?

    rm -f "$unit_list_tmp"

    return "$collection_status"
}

collect_process_inventory() {
    processes_tmp="$1"

    ps -eo pid=,ppid=,user=,group=,comm=,args= 2>/dev/null |
    jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(
            capture("^[[:space:]]*(?<pid>[0-9]+)[[:space:]]+(?<ppid>[0-9]+)[[:space:]]+(?<user>[^[:space:]]+)[[:space:]]+(?<group>[^[:space:]]+)[[:space:]]+(?<command>[^[:space:]]+)[[:space:]]*(?<args>.*)$")?
            | select(. != null)
            | {
                pid: (.pid | tonumber),
                ppid: (.ppid | tonumber),
                user: .user,
                group: .group,
                command: .command,
                args: .args
            }
        )
    ' > "$processes_tmp"
}

run_inventory_block() {
    inventory_hostname="$1"
    output_file="$2"

    echo "[+] Inventory command block started." >&2
    echo "[+] Inventory hostname: $inventory_hostname" >&2
    echo "[+] Writing inventory to: $output_file" >&2

    services_tmp="$(mktemp)" || {
        echo "[ERROR] Failed to create temporary file for service inventory." >&2
        exit 20
    }

    processes_tmp="$(mktemp)" || {
        echo "[ERROR] Failed to create temporary file for process inventory." >&2
        rm -f "$services_tmp"
        exit 21
    }

    cleanup_tmp_files() {
        rm -f "$services_tmp" "$processes_tmp"
    }

    trap cleanup_tmp_files EXIT

    echo "[*] Collecting systemd service inventory ..." >&2

    if ! collect_service_inventory "$services_tmp"; then
        echo "[ERROR] Failed while collecting service inventory." >&2
        exit 22
    fi

    if ! jq empty "$services_tmp" >/dev/null 2>&1; then
        echo "[ERROR] Service inventory JSON is invalid." >&2
        exit 23
    fi

    service_record_count="$(
        jq 'length' "$services_tmp" 2>/dev/null ||
            echo 0
    )"

    echo "[*] Service records collected: $service_record_count" >&2

    echo "[*] Collecting process inventory ..." >&2

    if ! collect_process_inventory "$processes_tmp"; then
        echo "[ERROR] Failed while collecting process inventory." >&2
        exit 24
    fi

    if ! jq empty "$processes_tmp" >/dev/null 2>&1; then
        echo "[ERROR] Process inventory JSON is invalid." >&2
        exit 25
    fi

    process_record_count="$(
        jq 'length' "$processes_tmp" 2>/dev/null ||
            echo 0
    )"

    echo "[*] Process records collected: $process_record_count" >&2

    if ! jq -n \
        --arg hostname "$inventory_hostname" \
        --arg collected_at "$(date '+%Y-%m-%d %H:%M:%S')" \
        --arg asset_type "linux_service_dependency_mapping" \
        --arg services_command "systemctl list-unit-files --type=service --no-legend --no-pager; systemctl show <unit>" \
        --slurpfile services "$services_tmp" \
        --arg processes_command "ps -eo pid=,ppid=,user=,group=,comm=,args=" \
        --slurpfile processes "$processes_tmp" \
        '{
            hostname: $hostname,
            collected_at: $collected_at,
            asset_type: $asset_type,
            service_inventory: {
                command: $services_command,
                exit_code: 0,
                records: $services[0]
            },
            process_inventory: {
                command: $processes_command,
                exit_code: 0,
                records: $processes[0]
            }
        }' > "$output_file"
    then
        echo "[ERROR] Failed to write JSON output: $output_file" >&2
        exit 26
    fi

    if [ ! -s "$output_file" ]; then
        echo "[ERROR] Output file is empty or missing: $output_file" >&2
        exit 27
    fi

    if ! jq empty "$output_file" >/dev/null 2>&1; then
        echo "[ERROR] Output file is not valid JSON: $output_file" >&2
        exit 28
    fi

    echo "[+] Inventory command block completed." >&2
    echo "[+] Inventory file: $output_file" >&2

    exit 0
}

if [ -z "$1" ]; then
    echo "[*] Running in local mode ..."
    echo "[*] Checking local dependencies ..."

    if ! check_dependencies; then
        echo "[ERROR] One or more required commands are not available on the local host." >&2
        echo "[INFO] On Debian or Ubuntu, install them with:" >&2
        echo "       sudo apt update && sudo apt install systemd procps jq coreutils gawk sed" >&2
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

    LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-service-dependency-mapping-results.json"

    echo "[+] Local hostname: $LOCAL_HOSTNAME"
    echo "[+] Local output file: $LOCAL_FILE"
    echo "[*] Starting local service dependency inventory ..."

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

    for command_name in bash systemctl ps jq hostname awk sed sort tr mktemp date; do
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
    echo "       sudo apt update && sudo apt install systemd procps jq coreutils gawk sed" >&2
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

REMOTE_FILE="/tmp/${SAFE_HOSTNAME}-service-dependency-mapping-results.json"
LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-service-dependency-mapping-results.json"

echo "[+] Remote hostname: $REMOTE_HOSTNAME"
echo "[+] Remote output file: $REMOTE_FILE"
echo "[+] Local output file: $LOCAL_FILE"
echo "[*] Starting remote service dependency inventory ..."

{
    declare -f collect_service_inventory
    declare -f collect_process_inventory
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

echo "[*] Validating remote JSON file ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" "jq empty '$REMOTE_FILE' >/dev/null 2>&1"; then
    echo "[ERROR] Remote inventory file is not valid JSON: $REMOTE_FILE" >&2
    exit 1
fi

echo "[*] Retrieving ${SAFE_HOSTNAME}-service-dependency-mapping-results.json ..."

if ! scp "${SSH_OPTS[@]}" -- "$TARGET:$REMOTE_FILE" "$LOCAL_FILE"; then
    echo "[ERROR] scp failed while retrieving: $REMOTE_FILE" >&2
    exit 1
fi

if [ ! -s "$LOCAL_FILE" ]; then
    echo "[ERROR] Retrieved file is empty or missing: $LOCAL_FILE" >&2
    exit 1
fi

if ! jq empty "$LOCAL_FILE" >/dev/null 2>&1; then
    echo "[ERROR] Retrieved file is not valid JSON: $LOCAL_FILE" >&2
    exit 1
fi

LOCAL_SERVICE_COUNT="$(
    jq '.service_inventory.records | length' "$LOCAL_FILE" 2>/dev/null ||
        echo 0
)"

LOCAL_PROCESS_COUNT="$(
    jq '.process_inventory.records | length' "$LOCAL_FILE" 2>/dev/null ||
        echo 0
)"

echo "[+] Inventory file retrieved successfully."
echo "[+] Local service records: $LOCAL_SERVICE_COUNT"
echo "[+] Local process records: $LOCAL_PROCESS_COUNT"

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
sudo chmod +x service_dependency_mapping.sh
sudo ./service_dependency_mapping.sh # Local Inventory
sudo ./service_dependency_mapping.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

{% hint style="info" %}
see service logs
{% endhint %}

```bash
journalctl -u <service-name>
```
