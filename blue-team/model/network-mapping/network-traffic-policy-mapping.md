# Network Traffic Policy Mapping

## Cheatsheet

### Local & Remote Windows Network Traffic Policy Mapping

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Gather Firewall profiles status, active rules and listening Ports with Process Name
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows Network Traffic Policy Mapping Script.

.DESCRIPTION
    Performs Windows Network Traffic Policy Mapping for local and remote hosts.
    Collects firewall profile configuration, active firewall rules, and listening
    TCP ports with owning process information, and writes the consolidated result
    as a single JSON object per host.

.EXAMPLE
    .\network-policy-mapping.ps1

.EXAMPLE
    .\network-policy-mapping.ps1 HOST-01,HOST-02,192.168.1.10

.OUTPUT
    inventory_results\<hostname>-network-traffic-policy-mapping.json
#>

param(
    [Parameter(Position = 0, Mandatory = $false)]
    [string[]]$ComputerName
)

$OutputDirectory = Join-Path -Path (Get-Location) -ChildPath "inventory_results"

if (-not (Test-Path -Path $OutputDirectory)) {
    try {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Gray
    }
    catch {
        throw "Failed to create directory $OutputDirectory. Please check permissions."
    }
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name.Trim() -replace '[\\/:*?"<>|]', '_')
}

function Read-CliCredentialForTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Write-Host ""
    Write-Host "Enter credentials for target: $Target" -ForegroundColor Cyan

    $UserName = Read-Host "Username for $Target, for example DOMAIN\User or $Target\Administrator"
    $Password = Read-Host "Password for $Target" -AsSecureString

    return New-Object System.Management.Automation.PSCredential ($UserName, $Password)
}

$NetworkPolicyMappingScript = {
    function Get-ProfileString {
        param($ProfileNumber)

        switch ($ProfileNumber) {
            1          { "Domain" }
            2          { "Private" }
            4          { "Public" }
            3          { "Domain, Private" }
            5          { "Domain, Public" }
            6          { "Private, Public" }
            7          { "Any" }
            2147483647 { "Any" }
            default    { "Unknown ($ProfileNumber)" }
        }
    }

    function Get-TcpStateString {
        param($StateNumber)

        switch ($StateNumber) {
            0       { "Closed" }
            1       { "Listen" }
            2       { "SynSent" }
            3       { "SynReceived" }
            4       { "Established" }
            5       { "FinWait1" }
            6       { "FinWait2" }
            7       { "CloseWait" }
            8       { "Closing" }
            9       { "LastAck" }
            10      { "TimeWait" }
            default { "Unknown ($StateNumber)" }
        }
    }

    function Get-SafeData {
        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$Script
        )

        try {
            & $Script
        }
        catch {
            $null
        }
    }

    $FirewallProfiles = Get-SafeData {
        Get-NetFirewallProfile |
            Select-Object `
                @{Name = 'Name'; Expression = { $_.Name.ToString() }},
                @{Name = 'Enabled'; Expression = { $_.Enabled.ToString() }},
                @{Name = 'DefaultInboundAction'; Expression = { $_.DefaultInboundAction.ToString() }},
                @{Name = 'DefaultOutboundAction'; Expression = { $_.DefaultOutboundAction.ToString() }},
                @{Name = 'LogAllowed'; Expression = { $_.LogAllowed.ToString() }},
                @{Name = 'LogBlocked'; Expression = { $_.LogBlocked.ToString() }},
                @{Name = 'LogFileName'; Expression = { $_.LogFileName }}
    }

    $ActiveFirewallRules = Get-SafeData {
        Get-NetFirewallRule |
            Where-Object { $_.Enabled -eq $true } |
            Select-Object `
                DisplayName,
                Name,
                @{Name = 'Direction'; Expression = { $_.Direction.ToString() }},
                @{Name = 'Action'; Expression = { $_.Action.ToString() }},
                @{Name = 'Profile'; Expression = { Get-ProfileString $_.Profile }},
                @{Name = 'Enabled'; Expression = { $_.Enabled.ToString() }},
                @{Name = 'PolicyStoreSource'; Expression = { $_.PolicyStoreSource }},
                @{Name = 'PolicyStoreSourceType'; Expression = { $_.PolicyStoreSourceType.ToString() }} |
            Sort-Object Direction, Action, DisplayName
    }

    $ListeningPorts = Get-SafeData {
        Get-NetTCPConnection -State Listen |
            Select-Object `
                LocalAddress,
                LocalPort,
                @{Name = 'State'; Expression = { Get-TcpStateString $_.State }},
                @{Name = 'PID'; Expression = { [string]$_.OwningProcess }},
                @{Name = 'ProcessName'; Expression = {
                    $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

                    if ($Process) {
                        $Process.ProcessName
                    }
                    else {
                        "Unknown"
                    }
                }},
                @{Name = 'ProcessPath'; Expression = {
                    $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue

                    if ($Process -and $Process.Path) {
                        $Process.Path
                    }
                    else {
                        "N/A"
                    }
                }} |
            Sort-Object LocalPort, LocalAddress
    }

    [PSCustomObject]@{
        Hostname              = $env:COMPUTERNAME
        CollectionTimeUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ReportType            = "Network Traffic Policy Mapping"
        CollectionMode        = "Windows PowerShell"
        FirewallProfilesCount = @($FirewallProfiles).Count
        ActiveRulesCount      = @($ActiveFirewallRules).Count
        ListeningPortsCount   = @($ListeningPorts).Count
        FirewallProfiles      = @($FirewallProfiles)
        ActiveFirewallRules   = @($ActiveFirewallRules)
        ListeningPorts        = @($ListeningPorts)
    }
}

function Save-NetworkPolicyMappingReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Report.Hostname)) {
        Write-Host "Skipping report because hostname is empty." -ForegroundColor Red
        return
    }

    $SafeHostname = ConvertTo-SafeFileName -Name $Report.Hostname
    $OutputPath = Join-Path -Path $OutputDirectory -ChildPath "$SafeHostname-network-traffic-policy-mapping.json"

    try {
        $Report |
            ConvertTo-Json -Depth 10 |
            Out-File -FilePath $OutputPath -Encoding UTF8

        Write-Host "Network policy mapping saved: $OutputPath" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Failed to save report for $($Report.Hostname): $($_.Exception.Message)" -ForegroundColor Red
    }
}

$Targets = @()

if ($ComputerName) {
    $Targets = @(
        $ComputerName |
            ForEach-Object {
                $_ -split ','
            } |
            ForEach-Object {
                $_.Trim().
                    Replace("`r", "").
                    Replace("`n", "").
                    Replace("[", "").
                    Replace("]", "")
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Select-Object -Unique
    )
}

if ($Targets.Count -eq 0) {
    Write-Host "[*] Running in local mode ..." -ForegroundColor Cyan

    try {
        $LocalResult = & $NetworkPolicyMappingScript

        if ($null -eq $LocalResult) {
            throw "Local Network Traffic Policy Mapping returned no data."
        }

        Save-NetworkPolicyMappingReport -Report $LocalResult -OutputDirectory $OutputDirectory

        Write-Host "[+] Local Network Traffic Policy Mapping complete." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Local Network Traffic Policy Mapping failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    exit 0
}

Write-Host "[*] Running in remote mode ..." -ForegroundColor Cyan
Write-Host "[+] Validated target systems: $($Targets -join ', ')" -ForegroundColor Cyan

$Results = @()

foreach ($Target in $Targets) {
    Write-Host ""
    Write-Host "[*] Processing target: $Target" -ForegroundColor Cyan

    $Result = $null

    try {
        $Result = Invoke-Command `
            -ComputerName $Target `
            -ScriptBlock $NetworkPolicyMappingScript `
            -ErrorAction Stop

        if ($null -ne $Result) {
            $Results += $Result
            Write-Host "[+] Success using current context: $Target" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[WARNING] Current context failed for ${Target}: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    if ($null -eq $Result) {
        try {
            $TargetCredential = Read-CliCredentialForTarget -Target $Target

            $Result = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $NetworkPolicyMappingScript `
                -Credential $TargetCredential `
                -ErrorAction Stop

            if ($null -ne $Result) {
                $Results += $Result
                Write-Host "[+] Success using provided credentials: $Target" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[ERROR] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

if ($Results.Count -eq 0) {
    Write-Host "[ERROR] No remote reports were collected." -ForegroundColor Red
    exit 1
}

foreach ($Result in $Results) {
    Save-NetworkPolicyMappingReport -Report $Result -OutputDirectory $OutputDirectory
}

Write-Host ""
Write-Host "[+] Remote Network Traffic Policy Mapping complete." -ForegroundColor Green
Write-Host "[+] Reports saved to: $OutputDirectory" -ForegroundColor Green
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
notepad network_traffic_policy_mapping.ps1
.\network_traffic_policy_mapping.ps1 # Local Inventory
.\network_traffic_policy_mapping.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Linux Network Traffic Policy Mapping

#### [nft](https://www.netfilter.org/projects/nftables/manpage.html) & [iptables](https://man7.org/linux/man-pages/man8/iptables.8.html) & [ip6tables](https://linux.die.net/man/8/ip6tables) & [ufw](https://wiki.ubuntu.com/UncomplicatedFirewall?action=show\&redirect=UbuntuFirewall)

{% hint style="info" %}
Collect firewall backend status, firewall rulesets, UFW status, listening TCP/UDP ports, owning PIDs & process names
{% endhint %}

```bash
#!/bin/bash

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local directory: $LOCAL_DIR" >&2
    exit 1
}

make_safe_hostname() {
    printf '%s' "$1" |
        tr -d '\r\n' |
        sed 's/[^A-Za-z0-9._-]/_/g'
}

run_network_policy_mapping_block() {
    inventory_hostname="$1"
    output_file="$2"

    echo "[+] Network Traffic Policy Mapping block started." >&2
    echo "[+] Inventory hostname: $inventory_hostname" >&2
    echo "[+] Writing report to: $output_file" >&2

    output_dir="$(dirname "$output_file")"

    if ! mkdir -p "$output_dir"; then
        echo "[ERROR] Cannot create output directory: $output_dir" >&2
        exit 10
    fi

    if ! : > "$output_file"; then
        echo "[ERROR] Cannot create output file: $output_file" >&2
        exit 11
    fi

    COLLECTION_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    to_json_lines() {
        sed $'s/\t/    /g' | jq -R -s 'split("\n")[:-1]'
    }

    run_privileged_command() {
        if command -v sudo >/dev/null 2>&1; then
            sudo -n "$@" 2>/dev/null
        else
            "$@" 2>/dev/null
        fi
    }

    echo "[*] Detecting firewall backend ..." >&2

    if command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_BACKEND="iptables"
    elif command -v ufw >/dev/null 2>&1; then
        FIREWALL_BACKEND="ufw"
    else
        FIREWALL_BACKEND="none"
    fi

    echo "[+] Firewall backend: $FIREWALL_BACKEND" >&2

    echo "[*] Collecting nftables ruleset ..." >&2

    NFT_RULESET_JSON="$(
        if command -v nft >/dev/null 2>&1; then
            run_privileged_command nft list ruleset | to_json_lines
        else
            echo '[]'
        fi
    )"

    if [ -z "$NFT_RULESET_JSON" ]; then
        NFT_RULESET_JSON='[]'
    fi

    echo "[*] Collecting iptables-save output ..." >&2

    IPTABLES_SAVE_JSON="$(
        if command -v iptables-save >/dev/null 2>&1; then
            run_privileged_command iptables-save | to_json_lines
        else
            echo '[]'
        fi
    )"

    if [ -z "$IPTABLES_SAVE_JSON" ]; then
        IPTABLES_SAVE_JSON='[]'
    fi

    echo "[*] Collecting ip6tables-save output ..." >&2

    IP6TABLES_SAVE_JSON="$(
        if command -v ip6tables-save >/dev/null 2>&1; then
            run_privileged_command ip6tables-save | to_json_lines
        else
            echo '[]'
        fi
    )"

    if [ -z "$IP6TABLES_SAVE_JSON" ]; then
        IP6TABLES_SAVE_JSON='[]'
    fi

    echo "[*] Collecting verbose iptables list ..." >&2

    IPTABLES_LIST_VERBOSE_JSON="$(
        if command -v iptables >/dev/null 2>&1; then
            run_privileged_command iptables -L -n -v --line-numbers | to_json_lines
        else
            echo '[]'
        fi
    )"

    if [ -z "$IPTABLES_LIST_VERBOSE_JSON" ]; then
        IPTABLES_LIST_VERBOSE_JSON='[]'
    fi

    echo "[*] Collecting UFW status ..." >&2

    UFW_STATUS_VERBOSE_JSON="$(
        if command -v ufw >/dev/null 2>&1; then
            run_privileged_command ufw status verbose | to_json_lines
        else
            echo '[]'
        fi
    )"

    if [ -z "$UFW_STATUS_VERBOSE_JSON" ]; then
        UFW_STATUS_VERBOSE_JSON='[]'
    fi

    echo "[*] Collecting listening ports and owning processes ..." >&2

    LISTENING_PORTS="$(
        if command -v ss >/dev/null 2>&1; then
            run_privileged_command ss -tulpenH | awk '
            BEGIN {
                print "["
                first=1
            }
            {
                proto=$1
                state=$2
                localaddr=$5
                peeraddr=$6

                pid=""
                procname=""

                if (match($0, /pid=[0-9]+/)) {
                    pid=substr($0, RSTART+4, RLENGTH-4)
                }

                if (match($0, /"[^"]+"/)) {
                    procname=substr($0, RSTART+1, RLENGTH-2)
                }

                gsub(/\\/,"\\\\",proto)
                gsub(/"/,"\\\"",proto)

                gsub(/\\/,"\\\\",state)
                gsub(/"/,"\\\"",state)

                gsub(/\\/,"\\\\",localaddr)
                gsub(/"/,"\\\"",localaddr)

                gsub(/\\/,"\\\\",peeraddr)
                gsub(/"/,"\\\"",peeraddr)

                gsub(/\\/,"\\\\",pid)
                gsub(/"/,"\\\"",pid)

                gsub(/\\/,"\\\\",procname)
                gsub(/"/,"\\\"",procname)

                if (first==0) {
                    printf(",\n")
                }

                first=0

                printf("  {")
                printf("\"Protocol\":\"%s\",", proto)
                printf("\"State\":\"%s\",", state)
                printf("\"LocalAddress\":\"%s\",", localaddr)
                printf("\"PeerAddress\":\"%s\",", peeraddr)
                printf("\"PID\":\"%s\",", pid)
                printf("\"ProcessName\":\"%s\"", procname)
                printf("}")
            }
            END {
                print "\n]"
            }
            '
        else
            echo '[]'
        fi
    )"

    if [ -z "$LISTENING_PORTS" ]; then
        LISTENING_PORTS='[]'
    fi

    echo "[*] Building final JSON document ..." >&2

    if ! jq -n \
        --arg Hostname "$inventory_hostname" \
        --arg CollectionTimeUtc "$COLLECTION_TIME" \
        --arg ReportType "Network Traffic Policy Mapping" \
        --arg FirewallBackend "$FIREWALL_BACKEND" \
        --argjson NftListRuleset "$NFT_RULESET_JSON" \
        --argjson IptablesSave "$IPTABLES_SAVE_JSON" \
        --argjson Ip6tablesSave "$IP6TABLES_SAVE_JSON" \
        --argjson IptablesListVerbose "$IPTABLES_LIST_VERBOSE_JSON" \
        --argjson UfwStatusVerbose "$UFW_STATUS_VERBOSE_JSON" \
        --argjson ListeningPorts "$LISTENING_PORTS" \
        '{
            Hostname: $Hostname,
            CollectionTimeUtc: $CollectionTimeUtc,
            ReportType: $ReportType,
            FirewallBackend: $FirewallBackend,
            FirewallData: {
                NftListRuleset: $NftListRuleset,
                IptablesSave: $IptablesSave,
                Ip6tablesSave: $Ip6tablesSave,
                IptablesListVerbose: $IptablesListVerbose,
                UfwStatusVerbose: $UfwStatusVerbose
            },
            ListeningPortsCount: ($ListeningPorts | length),
            ListeningPorts: $ListeningPorts
        }' > "$output_file"
    then
        echo "[ERROR] jq failed while building final JSON report." >&2
        exit 12
    fi

    if [ ! -s "$output_file" ]; then
        echo "[ERROR] Output file is missing or empty: $output_file" >&2
        exit 13
    fi

    echo "[+] Network Traffic Policy Mapping completed." >&2
    echo "[+] Report file: $output_file" >&2

    exit 0
}

check_dependencies() {
    missing=0

    for command_name in bash jq hostname date sed tr mkdir dirname; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing dependency: $command_name" >&2
            missing=1
        fi
    done

    return "$missing"
}

check_optional_tools() {
    for command_name in ss nft iptables iptables-save ip6tables-save ufw sudo; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[WARNING] Optional tool not found: $command_name" >&2
        fi
    done
}

if [ -z "$1" ]; then
    echo "[*] Running in local mode ..."
    echo "[*] Checking local dependencies ..."

    if ! check_dependencies; then
        echo "[ERROR] One or more required commands are not available on the local host." >&2
        echo "[INFO] On Debian or Ubuntu, install required packages with:" >&2
        echo "       sudo apt update && sudo apt install jq iproute2 nftables iptables ufw" >&2
        exit 1
    fi

    echo "[*] Checking optional local tools ..."
    check_optional_tools

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

    LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-network-traffic-policy-mapping.json"

    echo "[+] Local hostname: $LOCAL_HOSTNAME"
    echo "[+] Local output file: $LOCAL_FILE"
    echo "[*] Starting local Network Traffic Policy Mapping ..."

    run_network_policy_mapping_block "$LOCAL_HOSTNAME" "$LOCAL_FILE"
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

    for command_name in bash jq hostname date sed tr mkdir dirname; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing remote dependency: $command_name" >&2
            missing=1
        fi
    done

    exit "$missing"
'
then
    echo "[ERROR] One or more required commands are not available on the remote host." >&2
    echo "[INFO] On Debian or Ubuntu, install required packages with:" >&2
    echo "       sudo apt update && sudo apt install jq iproute2 nftables iptables ufw" >&2
    exit 1
fi

echo "[*] Checking optional remote tools ..."

ssh "${SSH_OPTS[@]}" "$TARGET" '
    for command_name in ss nft iptables iptables-save ip6tables-save ufw sudo; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[WARNING] Optional remote tool not found: $command_name" >&2
        fi
    done
' || true

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

REMOTE_FILE="/tmp/${SAFE_HOSTNAME}-network-traffic-policy-mapping.json"
LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-network-traffic-policy-mapping.json"

echo "[+] Remote hostname: $REMOTE_HOSTNAME"
echo "[+] Remote output file: $REMOTE_FILE"
echo "[+] Local output file: $LOCAL_FILE"
echo "[*] Starting remote Network Traffic Policy Mapping ..."

{
    declare -f run_network_policy_mapping_block
    printf 'run_network_policy_mapping_block "$1" "$2"\n'
} | ssh "${SSH_OPTS[@]}" "$TARGET" bash -s -- "$REMOTE_HOSTNAME" "$REMOTE_FILE"

SSH_EXIT=$?

if [ "$SSH_EXIT" -ne 0 ]; then
    echo "[ERROR] Remote Network Traffic Policy Mapping command failed." >&2
    echo "[ERROR] SSH exit code: $SSH_EXIT" >&2
    echo "[INFO] The script will not continue to scp." >&2
    exit 1
fi

echo "[+] Remote Network Traffic Policy Mapping completed successfully."
echo "[*] Verifying remote report file ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" "test -s '$REMOTE_FILE'"; then
    echo "[ERROR] Remote report file is missing or empty: $REMOTE_FILE" >&2
    exit 1
fi

echo "[*] Retrieving ${SAFE_HOSTNAME}-network-traffic-policy-mapping.json ..."

if ! scp "${SSH_OPTS[@]}" -- "$TARGET:$REMOTE_FILE" "$LOCAL_FILE"; then
    echo "[ERROR] scp failed while retrieving: $REMOTE_FILE" >&2
    exit 1
fi

if [ ! -s "$LOCAL_FILE" ]; then
    echo "[ERROR] Retrieved file is empty or missing: $LOCAL_FILE" >&2
    exit 1
fi

echo "[+] Report file retrieved successfully."
echo "[+] Local report file: $LOCAL_FILE"

echo "[*] Cleaning up remote report file ..."

if ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f -- '$REMOTE_FILE'"; then
    echo "[+] Remote report file removed."
else
    echo "[WARNING] Could not remove remote file: $REMOTE_FILE" >&2
fi

echo "[+] Network Traffic Policy Mapping complete."
echo "[+] Saved to: $LOCAL_FILE"
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
nano network_traffic_policy_mapping.sh
./network_traffic_policy_mapping.sh # Local Inventory
./network_traffic_policy_mapping.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

