# Data Exchange Mapping

## Cheat Sheet

### Local & Remote Windows Data Exchange Mapping

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect network connection details and routing table information
{% endhint %}

```powershell
<#
.SYNOPSIS
    Data Exchange Mapping Script.

.DESCRIPTION
    Collects network connection details and routing table information.
    Performs execution for local and remote hosts.
    Writes one valid JSON file per host.

.EXAMPLE
    .\data-exchange-mapping.ps1

.EXAMPLE
    .\data-exchange-mapping.ps1 HOST-01,HOST-02,192.168.1.10

.OUTPUT
    inventory_results\<hostname>-data-exchange-mapping-results.json
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

    if ($NormalizedTarget -eq "localhost") { return $true }
    if ($NormalizedTarget -eq ".") { return $true }
    if ($NormalizedTarget -eq $LocalComputerName) { return $true }

    return $false
}

$DataExchangeMappingScriptBlock = {
    # 1. Network Connections Parsing
    $ConnectionItems = New-Object System.Collections.Generic.List[object]
    $NetstatAbnoOutput = netstat -abno
    $ConnectionLines = $NetstatAbnoOutput | Select-String -Pattern '^\s*(TCP|UDP)\s+'

    foreach ($Line in $ConnectionLines) {
        $Tokens = $Line.ToString().Trim() -split '\s+'
        if ($Tokens.Count -lt 4) { continue }
        
        $Protocol = $Tokens[0]
        if ($Protocol -eq "TCP" -and $Tokens.Count -ge 5) {
            $ConnectionItems.Add([PSCustomObject]@{
                protocol        = $Tokens[0]
                local_address   = $Tokens[1]
                foreign_address = $Tokens[2]
                state           = $Tokens[3]
                pid             = $Tokens[4]
            })
        }
        elseif ($Protocol -eq "UDP" -and $Tokens.Count -ge 4) {
            $ConnectionItems.Add([PSCustomObject]@{
                protocol        = $Tokens[0]
                local_address   = $Tokens[1]
                foreign_address = $Tokens[2]
                state           = "N/A"
                pid             = $Tokens[3]
            })
        }
    }

    # 2. Routing Table (Stored as Array for JSON readability)
    $RouteTableRaw = netstat -r
    $RouteTableClean = $RouteTableRaw | Where-Object { $_.Trim() -ne "" }

    return [PSCustomObject]@{
        hostname              = $env:COMPUTERNAME
        asset_type            = "data_exchange_mapping"
        collection_time       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        commands_used         = @("netstat -abno", "netstat -r")
        network_connections   = $ConnectionItems
        routing_table         = $RouteTableClean
    }
}

# --- Main Execution Logic ---
foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $ResultObject = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $ResultObject = & $DataExchangeMappingScriptBlock
        }
        else {
            $ResultObject = Invoke-Command -ComputerName $Target -ScriptBlock $DataExchangeMappingScriptBlock -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[-] Current user context failed for $Target. Requesting credentials..." -ForegroundColor DarkGray
    }

    if ($null -eq $ResultObject -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target
            $ResultObject = Invoke-Command -ComputerName $Target -ScriptBlock $DataExchangeMappingScriptBlock -Credential $Credential -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $ResultObject -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local mapping from ${Target}." -ForegroundColor Red
        continue
    }

    if ($null -ne $ResultObject) {
        $FinalHostName = $ResultObject.hostname
        $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
        $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-data-exchange-mapping-results.json"

        try {
            $ResultObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
            Write-Host "[+] Data exchange mapping saved for ${FinalHostName}: $OutputFilePath" -ForegroundColor Green
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
notepad data-exchange-mapping.ps1
.\data-exchange-mapping.ps1 # Local Inventory
.\data-exchange-mapping.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Linux Data Exchange Mapping

#### [netstat](https://www.netstat.net/index.html) & [route](https://man7.org/linux/man-pages/man8/route.8.html)

{% hint style="info" %}
Collect network connection details and routing table information
{% endhint %}

```bash
#!/usr/bin/env bash

set -o pipefail

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local output directory: $LOCAL_DIR" >&2
    exit 1
}

make_safe_hostname() {
    printf '%s' "$1" |
        tr -d '\r\n' |
        sed 's/[^A-Za-z0-9._-]/_/g'
}

check_local_dependencies() {
    local missing=0
    local command_name

    for command_name in bash ss route awk jq hostname date tr sed mkdir mktemp ssh scp; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing local dependency: $command_name" >&2
            missing=1
        fi
    done

    return "$missing"
}

run_inventory_block() {
    local inventory_hostname="$1"
    local output_file="$2"
    local collection_time
    local services_active_ports_json
    local routing_table_json

    collection_time="$(date '+%Y-%m-%d %H:%M:%S')"

    echo "[+] Collecting network data from: ${inventory_hostname}" >&2

    services_active_ports_json="$(
        ss -tulpen 2>/dev/null |
            awk '
                NR == 1 && $1 == "Netid" {
                    next
                }

                NF >= 6 {
                    process=""

                    for (i = 7; i <= NF; i++) {
                        if (i == 7) {
                            process=$i
                        } else {
                            process=process " " $i
                        }
                    }

                    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, $6, process
                }
            ' |
            jq -R -s '
                split("\n")
                | map(select(length > 0))
                | map(split("\t"))
                | map({
                    netid: .[0],
                    state: .[1],
                    recv_q: .[2],
                    send_q: .[3],
                    local_address_port: .[4],
                    peer_address_port: .[5],
                    process: .[6]
                })
            '
    )"

    routing_table_json="$(
        route -n 2>/dev/null |
            awk '
                NR > 2 && NF >= 8 {
                    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, $6, $7, $8
                }
            ' |
            jq -R -s '
                split("\n")
                | map(select(length > 0))
                | map(split("\t"))
                | map({
                    destination: .[0],
                    gateway: .[1],
                    genmask: .[2],
                    flags: .[3],
                    metric: .[4],
                    ref: .[5],
                    use: .[6],
                    iface: .[7]
                })
            '
    )"

    if ! jq -n \
        --arg hostname "$inventory_hostname" \
        --arg asset_type "data_exchange_mapping" \
        --arg collection_time "$collection_time" \
        --argjson services_active_ports "$services_active_ports_json" \
        --argjson routing_table "$routing_table_json" \
        '{
            hostname: $hostname,
            asset_type: $asset_type,
            collection_time: $collection_time,
            commands_used: [
                "ss -tulpen",
                "route -n"
            ],
            services_active_ports: $services_active_ports,
            routing_table: $routing_table
        }' > "$output_file"
    then
        echo "[ERROR] Failed to create JSON output: $output_file" >&2
        return 1
    fi

    if ! jq empty "$output_file" >/dev/null 2>&1; then
        echo "[ERROR] Generated output is not valid JSON: $output_file" >&2
        return 1
    fi

    echo "[+] Inventory written to: $output_file" >&2
}

run_local_inventory() {
    local local_hostname
    local safe_hostname
    local output_file

    echo "[*] Running in local mode."

    if ! check_local_dependencies; then
        echo "[ERROR] Required local dependencies are missing." >&2
        exit 1
    fi

    local_hostname="$(
        hostname -s 2>/dev/null ||
            hostname 2>/dev/null ||
            printf '%s\n' "unknown-host"
    )"

    local_hostname="$(printf '%s' "$local_hostname" | tr -d '\r\n')"

    if [ -z "$local_hostname" ]; then
        local_hostname="unknown-host"
    fi

    safe_hostname="$(make_safe_hostname "$local_hostname")"

    if [ -z "$safe_hostname" ]; then
        safe_hostname="unknown-host"
    fi

    output_file="${LOCAL_DIR}/${safe_hostname}-data-exchange-mapping-results.json"

    run_inventory_block "$local_hostname" "$output_file" || {
        echo "[ERROR] Local inventory failed." >&2
        exit 1
    }

    echo "[+] Local inventory completed."
    echo "[+] Output: $output_file"
}

run_remote_inventory() {
    local target="$1"
    local control_dir
    local control_path
    local remote_hostname
    local safe_hostname
    local remote_file
    local local_file

    if ! check_local_dependencies; then
        echo "[ERROR] Required local dependencies are missing." >&2
        exit 1
    fi

    control_dir="$(mktemp -d)" || {
        echo "[ERROR] Failed to create SSH control directory." >&2
        exit 1
    }

    control_path="${control_dir}/ssh-control-%r@%h:%p"

    cleanup_remote_session() {
        ssh \
            -o ControlMaster=auto \
            -o ControlPath="$control_path" \
            -o ControlPersist=10m \
            -O exit "$target" >/dev/null 2>&1 || true

        rm -rf "$control_dir"
    }

    trap cleanup_remote_session EXIT

    echo "[*] Running in remote mode."
    echo "[*] Target: $target"
    echo "[*] Testing SSH connection ..."

    if ! ssh \
        -o ControlMaster=auto \
        -o ControlPath="$control_path" \
        -o ControlPersist=10m \
        -o ConnectTimeout=10 \
        "$target" \
        'printf "[+] SSH connection established on: "; hostname'
    then
        echo "[ERROR] SSH connection failed: $target" >&2
        exit 1
    fi

    echo "[*] Checking remote dependencies ..."

    if ! ssh \
        -o ControlMaster=auto \
        -o ControlPath="$control_path" \
        -o ControlPersist=10m \
        "$target" \
        'missing=0
         for command_name in bash ss route awk jq hostname date; do
             if ! command -v "$command_name" >/dev/null 2>&1; then
                 echo "[ERROR] Missing remote dependency: $command_name" >&2
                 missing=1
             fi
         done
         exit "$missing"'
    then
        echo "[ERROR] Required remote dependencies are missing." >&2
        exit 1
    fi

    remote_hostname="$(
        ssh \
            -o ControlMaster=auto \
            -o ControlPath="$control_path" \
            -o ControlPersist=10m \
            "$target" \
            'hostname -s 2>/dev/null || hostname 2>/dev/null || printf "%s\n" "unknown-host"'
    )"

    if [ "$?" -ne 0 ]; then
        echo "[ERROR] Failed to retrieve remote hostname." >&2
        exit 1
    fi

    remote_hostname="$(printf '%s' "$remote_hostname" | tr -d '\r\n')"

    if [ -z "$remote_hostname" ]; then
        remote_hostname="unknown-host"
    fi

    safe_hostname="$(make_safe_hostname "$remote_hostname")"

    if [ -z "$safe_hostname" ]; then
        safe_hostname="unknown-host"
    fi

    remote_file="/tmp/${safe_hostname}-data-exchange-mapping-results.json"
    local_file="${LOCAL_DIR}/${safe_hostname}-data-exchange-mapping-results.json"

    echo "[+] Remote hostname: $remote_hostname"
    echo "[+] Remote output: $remote_file"
    echo "[+] Local output: $local_file"
    echo "[*] Collecting remote network data ..."

    {
        declare -f run_inventory_block
        printf '%s\n' 'run_inventory_block "$1" "$2"'
    } |
        ssh \
            -o ControlMaster=auto \
            -o ControlPath="$control_path" \
            -o ControlPersist=10m \
            "$target" \
            bash -s -- "$remote_hostname" "$remote_file"

    if [ "$?" -ne 0 ]; then
        echo "[ERROR] Remote inventory collection failed." >&2
        exit 1
    fi

    echo "[*] Verifying remote JSON file ..."

    if ! ssh \
        -o ControlMaster=auto \
        -o ControlPath="$control_path" \
        -o ControlPersist=10m \
        "$target" \
        "test -s '$remote_file' && jq empty '$remote_file'"
    then
        echo "[ERROR] Remote output is missing, empty, or invalid JSON." >&2
        exit 1
    fi

    echo "[*] Downloading remote JSON file ..."

    if ! scp \
        -o ControlMaster=auto \
        -o ControlPath="$control_path" \
        -o ControlPersist=10m \
        "$target:$remote_file" \
        "$local_file"
    then
        echo "[ERROR] Failed to download remote output file." >&2
        exit 1
    fi

    if ! jq empty "$local_file" >/dev/null 2>&1; then
        echo "[ERROR] Downloaded file is not valid JSON." >&2
        exit 1
    fi

    echo "[*] Removing temporary remote file ..."

    ssh \
        -o ControlMaster=auto \
        -o ControlPath="$control_path" \
        -o ControlPersist=10m \
        "$target" \
        "rm -f -- '$remote_file'" || {
            echo "[WARNING] Failed to remove remote file: $remote_file" >&2
        }

    echo "[+] Remote inventory completed."
    echo "[+] Output: $local_file"
}

if [ "$#" -eq 0 ]; then
    run_local_inventory
else
    run_remote_inventory "$1"
fi
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
nano data-exchange-mapping.sh
./data-exchange-mapping.sh # Local Inventory
data-exchange-mapping.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

#### [Tcpdump](https://www.tcpdump.org/)

{% hint style="info" %}
Capture traffic
{% endhint %}

```bash
tcpdump -i any -nn -s 0 -w capture.pcap
```

#### [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

{% hint style="info" %}
Analyze tcp connections
{% endhint %}

```bash
tshark -r capture.pcap -q -z conv,tcp
```

{% hint style="info" %}
Extract dns requests
{% endhint %}

```bash
tshark -r capture.pcap -Y dns -T fields \
-e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type
```
