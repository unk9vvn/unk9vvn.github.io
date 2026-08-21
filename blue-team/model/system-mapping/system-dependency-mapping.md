# System Dependency Mapping

## Check List

* [ ] You can use the outputs of the Service Dependency Mapping cheat sheets and the Network Mapping topics along with the outputs of the cheat sheets in this section, since these topics are related and can help with a more accurate analysis

## Cheat Sheet

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

### Local & Remote Linux System Dependency Mapping

#### [ps](https://man7.org/linux/man-pages/man1/ps.1.html) & [ldd](https://man7.org/linux/man-pages/man1/ldd.1.html) & [ss](https://man7.org/linux/man-pages/man8/ss.8.html) & [readlink](https://man7.org/linux/man-pages/man1/readlink.1.html) & [lsmod](https://man7.org/linux/man-pages/man8/lsmod.8.html) & [modinfo](https://man7.org/linux/man-pages/man8/modinfo.8.html) & [systemctl](https://man7.org/linux/man-pages/man1/systemctl.1.html)

{% hint style="info" %}
Collect structured configuration data on running processes, binary linkage chains, network sockets, loaded shared libraries, kernel modules and systemd timers
{% endhint %}

```bash
#!/bin/bash

LOCAL_DIR="./inventory_results"
mkdir -p "$LOCAL_DIR" || exit 1

check_dependencies() {
    for cmd in bash hostname ps ldd ss awk jq mktemp readlink lsmod modinfo systemctl sed grep sort tr head cat; do
        command -v "$cmd" >/dev/null 2>&1 || return 1
    done
    return 0
}

make_safe_hostname() {
    printf '%s' "$1" | tr -d '\r\n' | sed 's/[^A-Za-z0-9._-]/_/g'
}

json_array_from_jsonl() {
    local input_file="$1"
    local output_file="$2"

    if [ -s "$input_file" ]; then
        jq -s '.' "$input_file" > "$output_file"
    else
        printf '[]\n' > "$output_file"
    fi
}

collect_tcp_jsonl() {
    local output_file="$1"
    local line state local_addr remote_addr pid process

    ss -tanpH 2>/dev/null | while IFS= read -r line; do
        state="$(printf '%s\n' "$line" | awk '{print $1}')"
        local_addr="$(printf '%s\n' "$line" | awk '{print $4}')"
        remote_addr="$(printf '%s\n' "$line" | awk '{print $5}')"
        pid="$(printf '%s\n' "$line" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n1)"
        process="$(printf '%s\n' "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1)"

        [ -n "$pid" ] || pid="-"
        [ -n "$process" ] || process="-"

        jq -cn \
            --arg state "$state" \
            --arg local "$local_addr" \
            --arg remote "$remote_addr" \
            --arg pid "$pid" \
            --arg process "$process" \
            '{state: $state, local: $local, remote: $remote, pid: $pid, process: $process}' >> "$output_file"
    done
}

collect_udp_jsonl() {
    local output_file="$1"
    local line state local_addr remote_addr pid process

    ss -uanpH 2>/dev/null | while IFS= read -r line; do
        state="$(printf '%s\n' "$line" | awk '{print $1}')"
        local_addr="$(printf '%s\n' "$line" | awk '{print $5}')"
        remote_addr="$(printf '%s\n' "$line" | awk '{print $6}')"
        pid="$(printf '%s\n' "$line" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n1)"
        process="$(printf '%s\n' "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1)"

        [ -n "$local_addr" ] || local_addr="-"
        [ -n "$remote_addr" ] || remote_addr="-"
        [ -n "$pid" ] || pid="-"
        [ -n "$process" ] || process="-"

        jq -cn \
            --arg state "$state" \
            --arg local "$local_addr" \
            --arg remote "$remote_addr" \
            --arg pid "$pid" \
            --arg process "$process" \
            '{state: $state, local: $local, remote: $remote, pid: $pid, process: $process}' >> "$output_file"
    done
}

run_inventory_block() {
    local inv_hostname="$1"
    local final_output="$2"
    local tmp_dir
    local proc_jsonl tcp_jsonl udp_jsonl mods_jsonl drivers_jsonl tasks_jsonl
    local pid ppid comm args exe deps_list pname libs mod info path desc deps line timer service state

    tmp_dir="$(mktemp -d)" || exit 1

    proc_jsonl="$tmp_dir/proc.jsonl"
    tcp_jsonl="$tmp_dir/tcp.jsonl"
    udp_jsonl="$tmp_dir/udp.jsonl"
    mods_jsonl="$tmp_dir/mods.jsonl"
    drivers_jsonl="$tmp_dir/drivers.jsonl"
    tasks_jsonl="$tmp_dir/tasks.jsonl"

    : > "$proc_jsonl"
    : > "$tcp_jsonl"
    : > "$udp_jsonl"
    : > "$mods_jsonl"
    : > "$drivers_jsonl"
    : > "$tasks_jsonl"

    ps -eo pid=,ppid=,comm=,args= | while read -r pid ppid comm args; do
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
        deps_list=""

        if [ -n "$exe" ] && [ -f "$exe" ] && [ -x "$exe" ]; then
            deps_list="$(ldd "$exe" 2>/dev/null | awk '/=>/ {print $1} /^[[:space:]]*\/.*$/ {print $1}' | tr '\n' '|')"
        fi

        jq -cn \
            --arg pid "$pid" \
            --arg ppid "$ppid" \
            --arg process "$comm" \
            --arg command "$args" \
            --arg executable "${exe:-N/A}" \
            --arg deps "$deps_list" \
            '{pid: $pid, ppid: $ppid, process: $process, command: $command, executable: $executable, dependencies: ($deps | split("|") | map(select(length > 0)))}' >> "$proc_jsonl"
    done

    collect_tcp_jsonl "$tcp_jsonl"
    collect_udp_jsonl "$udp_jsonl"

    for pid in $(ps -e -o pid=); do
        [ -d "/proc/$pid" ] || continue
        pname="$(cat "/proc/$pid/comm" 2>/dev/null)"
        [ -n "$pname" ] || continue
        libs="$(awk '{print $NF}' "/proc/$pid/maps" 2>/dev/null | grep -E '\.so(\.[0-9]+)*$' | sort -u | tr '\n' '|')"
        [ -n "$libs" ] || continue

        jq -cn \
            --arg pid "$pid" \
            --arg process "$pname" \
            --arg modules "$libs" \
            '{pid: $pid, process: $process, modules: ($modules | split("|") | map(select(length > 0)))}' >> "$mods_jsonl"
    done

    lsmod | awk 'NR>1 {print $1}' | while read -r mod; do
        info="$(modinfo "$mod" 2>/dev/null)"
        path="$(printf '%s\n' "$info" | awk -F': ' '/^filename:/ {print $2; exit}')"
        desc="$(printf '%s\n' "$info" | awk -F': ' '/^description:/ {print $2; exit}')"
        deps="$(printf '%s\n' "$info" | awk -F':' '/^depends:/ {print $2; exit}' | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr '\n' '|')"

        jq -cn \
            --arg module "$mod" \
            --arg path "$path" \
            --arg description "$desc" \
            --arg depends "$deps" \
            '{module: $module, path: $path, description: $description, depends_on: ($depends | split("|") | map(select(length > 0)))}' >> "$drivers_jsonl"
    done

    systemctl list-timers --all --no-legend --no-pager 2>/dev/null | while read -r line; do
        timer="$(printf '%s\n' "$line" | awk '{print $(NF-1)}')"
        [[ "$timer" == *.timer ]] || continue
        service="$(systemctl show "$timer" -p Unit --value 2>/dev/null)"
        state="$(systemctl show "$timer" -p ActiveState --value 2>/dev/null)"

        jq -cn \
            --arg timer "$timer" \
            --arg service "$service" \
            --arg state "$state" \
            '{timer: $timer, service: $service, state: $state}' >> "$tasks_jsonl"
    done

    json_array_from_jsonl "$proc_jsonl" "$tmp_dir/proc.array.json"
    json_array_from_jsonl "$tcp_jsonl" "$tmp_dir/tcp.array.json"
    json_array_from_jsonl "$udp_jsonl" "$tmp_dir/udp.array.json"
    json_array_from_jsonl "$mods_jsonl" "$tmp_dir/mods.array.json"
    json_array_from_jsonl "$drivers_jsonl" "$tmp_dir/drivers.array.json"
    json_array_from_jsonl "$tasks_jsonl" "$tmp_dir/tasks.array.json"

    jq -n \
        --arg hostname "$inv_hostname" \
        --arg asset_type "system-dependency-mapping" \
        --slurpfile processes "$tmp_dir/proc.array.json" \
        --slurpfile tcp_connections "$tmp_dir/tcp.array.json" \
        --slurpfile udp_endpoints "$tmp_dir/udp.array.json" \
        --slurpfile process_modules "$tmp_dir/mods.array.json" \
        --slurpfile drivers "$tmp_dir/drivers.array.json" \
        --slurpfile scheduled_tasks "$tmp_dir/tasks.array.json" \
        '{
            hostname: $hostname,
            asset_type: $asset_type,
            processes: ($processes[0] // []),
            tcp_connections: ($tcp_connections[0] // []),
            udp_endpoints: ($udp_endpoints[0] // []),
            process_modules: ($process_modules[0] // []),
            drivers: ($drivers[0] // []),
            scheduled_tasks: ($scheduled_tasks[0] // [])
        }' > "$final_output"

    rm -rf "$tmp_dir"
}

open_ssh_master() {
    local target="$1"
    local control_path="$2"

    ssh \
        -o ControlMaster=yes \
        -o ControlPersist=600 \
        -o ControlPath="$control_path" \
        -o StrictHostKeyChecking=accept-new \
        -Nf "$target"
}

ssh_master_run() {
    local target="$1"
    local control_path="$2"
    shift 2

    ssh \
        -o ControlMaster=no \
        -o ControlPath="$control_path" \
        "$target" "$@"
}

scp_master_upload() {
    local control_path="$1"
    local local_file="$2"
    local target="$3"
    local remote_file="$4"

    scp \
        -o ControlMaster=no \
        -o ControlPath="$control_path" \
        "$local_file" "$target:$remote_file"
}

scp_master_download() {
    local control_path="$1"
    local target="$2"
    local remote_file="$3"
    local local_dir="$4"

    scp \
        -o ControlMaster=no \
        -o ControlPath="$control_path" \
        "$target:$remote_file" "$local_dir/"
}

close_ssh_master() {
    local target="$1"
    local control_path="$2"

    ssh -o ControlPath="$control_path" -O exit "$target" >/dev/null 2>&1 || true
}

if [ -z "$1" ]; then
    echo "Running local system dependency mapping..."
    check_dependencies || {
        echo "Error: Local host is missing required system utilities."
        exit 1
    }

    LOCAL_RAW_HN="$(hostname -s)"
    SAFE_HN="$(make_safe_hostname "$LOCAL_RAW_HN")"
    OUTPUT_FILE="${LOCAL_DIR}/${SAFE_HN}-system-dependency-mapping.json"

    run_inventory_block "$LOCAL_RAW_HN" "$OUTPUT_FILE"

    if [ ! -s "$OUTPUT_FILE" ]; then
        echo "Error: Inventory output is empty or failed to generate."
        exit 1
    fi

    echo "Inventory complete. Saved to: $OUTPUT_FILE"
else
    TARGET="$1"
    CONTROL_DIR="$(mktemp -d)" || exit 1
    CONTROL_PATH="$CONTROL_DIR/ssh_mux.sock"
    LOCAL_PAYLOAD="$(mktemp)" || exit 1
    REMOTE_SCRIPT_FILE="/tmp/system_dependency_mapping_remote_$$.sh"

    cleanup() {
        rm -f "$LOCAL_PAYLOAD"
        close_ssh_master "$TARGET" "$CONTROL_PATH"
        rm -rf "$CONTROL_DIR"
    }
    trap cleanup EXIT

    echo "Connecting to $TARGET to perform system dependency mapping..."

    open_ssh_master "$TARGET" "$CONTROL_PATH" || {
        echo "Error: Failed to establish SSH master connection."
        exit 1
    }

    {
        declare -f check_dependencies
        declare -f make_safe_hostname
        declare -f json_array_from_jsonl
        declare -f collect_tcp_jsonl
        declare -f collect_udp_jsonl
        declare -f run_inventory_block
        cat <<'EOF'
check_dependencies || {
    echo "Error: Remote target is missing required system utilities."
    exit 1
}

REMOTE_RAW_HN="$(hostname -s)"
SAFE_HN="$(make_safe_hostname "$REMOTE_RAW_HN")"
FILE_NAME="${SAFE_HN}-system-dependency-mapping.json"

run_inventory_block "$REMOTE_RAW_HN" "$FILE_NAME"
printf '%s\n' "$FILE_NAME"
EOF
    } > "$LOCAL_PAYLOAD"

    scp_master_upload "$CONTROL_PATH" "$LOCAL_PAYLOAD" "$TARGET" "$REMOTE_SCRIPT_FILE" >/dev/null || {
        echo "Error: Failed to upload remote execution payload."
        exit 1
    }

    ssh_master_run "$TARGET" "$CONTROL_PATH" "chmod +x '$REMOTE_SCRIPT_FILE'" >/dev/null || {
        echo "Error: Failed to set remote payload permissions."
        exit 1
    }

    REMOTE_FILE="$(ssh_master_run "$TARGET" "$CONTROL_PATH" "$REMOTE_SCRIPT_FILE" | tail -n1 | tr -d '\r\n')"

    if [ -z "$REMOTE_FILE" ]; then
        echo "Error: Remote inventory execution did not return an output filename."
        exit 1
    fi

    echo "Retrieving $REMOTE_FILE..."
    scp_master_download "$CONTROL_PATH" "$TARGET" "$REMOTE_FILE" "$LOCAL_DIR" >/dev/null || {
        echo "Error: Failed to retrieve remote inventory file."
        exit 1
    }

    if [ ! -s "$LOCAL_DIR/$REMOTE_FILE" ]; then
        echo "Error: Dependency mapping file was not retrieved or is empty: $LOCAL_DIR/$REMOTE_FILE"
        exit 1
    fi

    echo "Cleaning up remote host..."
    ssh_master_run "$TARGET" "$CONTROL_PATH" "rm -f '$REMOTE_FILE' '$REMOTE_SCRIPT_FILE'" >/dev/null 2>&1 || true

    echo "Inventory complete. Saved to: $LOCAL_DIR/$REMOTE_FILE"
fi
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
sudo chmod +x system_dependency_mapping.sh
sudo ./system_dependency_mapping.sh # Local Inventory
sudo ./system_dependency_mapping.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```
