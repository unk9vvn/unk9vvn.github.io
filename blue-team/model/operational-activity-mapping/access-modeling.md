# Access Modeling

## Cheatsheet

### Checklist

* [ ] For websites, identify and document the roles used by the application
* [ ] Review the granularity of those roles and the needs behind the permissions granted.

### Local & Remote Windows Access Modeling

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
Collect local users, local groups, Active Directory users, Domain Admins members, and SMB share access permissions
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows Access Modeling Inventory Script.

.DESCRIPTION
    Performs Access Modeling inventory for local and remote Windows hosts.
    Collects Local Users, Local Groups, Active Directory Users,
    Domain Admins members, and SMB Share Access information.
    Writes one JSON file per host.

.EXAMPLE
    .\access-modeling.ps1

.EXAMPLE
    .\access-modeling.ps1 HOST-01,HOST-02,192.168.1.10

.OUTPUT
    inventory_results\<hostname>-access-modeling-results.json
#>

param(
    [Parameter(Position = 0)]
    [string]$Targets
)

$ErrorActionPreference = 'Stop'

$OutputDir = "inventory_results"

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
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

$AccessModelingScriptBlock = {
    $ErrorActionPreference = 'Stop'

    function Get-SafeCollection {
        param(
            [scriptblock]$ScriptBlock,
            [string]$Name
        )

        try {
            @(& $ScriptBlock)
        }
        catch {
            Write-Warning "Failed to collect ${Name}: $($_.Exception.Message)"
            @()
        }
    }

    $Hostname = $env:COMPUTERNAME
    $Timestamp = (Get-Date).ToString("o")

    $LocalUsers = Get-SafeCollection -Name "local users" -ScriptBlock {
        Get-LocalUser | ForEach-Object {
            [ordered]@{
                Name                  = $_.Name
                Enabled               = $_.Enabled
                Description           = $_.Description
                LastLogon             = $_.LastLogon
                PasswordRequired      = $_.PasswordRequired
                PasswordLastSet       = $_.PasswordLastSet
                UserMayChangePassword = $_.UserMayChangePassword
                SID                   = $_.SID.Value
            }
        }
    }

    $LocalGroups = Get-SafeCollection -Name "local groups" -ScriptBlock {
        Get-LocalGroup | ForEach-Object {
            $groupName = $_.Name
            $groupDescription = $_.Description

            $members = Get-SafeCollection -Name "group members for ${groupName}" -ScriptBlock {
                Get-LocalGroupMember -Group $groupName | ForEach-Object {
                    [ordered]@{
                        Name            = $_.Name
                        ObjectClass     = $_.ObjectClass
                        PrincipalSource = $_.PrincipalSource.ToString()
                        SID             = $_.SID.Value
                    }
                }
            }

            [ordered]@{
                Group       = $groupName
                Description = $groupDescription
                Members     = @($members)
            }
        }
    }

    $ADUsers = Get-SafeCollection -Name "Active Directory users" -ScriptBlock {
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            Get-ADUser -Filter * | ForEach-Object {
                [ordered]@{
                    SamAccountName    = $_.SamAccountName
                    Name              = $_.Name
                    Enabled           = $_.Enabled
                    DistinguishedName = $_.DistinguishedName
                }
            }
        }
    }

    $DomainAdminsMembers = Get-SafeCollection -Name "Domain Admins members" -ScriptBlock {
        if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {
            Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object {
                [ordered]@{
                    Name              = $_.Name
                    SamAccountName    = $_.SamAccountName
                    ObjectClass       = $_.ObjectClass
                    DistinguishedName = $_.DistinguishedName
                }
            }
        }
    }

    $SMBShares = Get-SafeCollection -Name "SMB share access" -ScriptBlock {
        Get-SmbShare | ForEach-Object {
            $shareName = $_.Name

            $access = Get-SafeCollection -Name "share access for ${shareName}" -ScriptBlock {
                Get-SmbShareAccess -Name $shareName | ForEach-Object {
                    [ordered]@{
                        AccountName       = $_.AccountName
                        AccessControlType = $_.AccessControlType.ToString()
                        AccessRight       = $_.AccessRight.ToString()
                    }
                }
            }

            [ordered]@{
                Share       = $shareName
                Path        = $_.Path
                Description = $_.Description
                Access      = @($access)
            }
        }
    }

    $Inventory = [ordered]@{
        hostname        = $Hostname
        collection_time = $Timestamp
        identity_inventory = [ordered]@{
            local_users            = @($LocalUsers)
            local_groups           = @($LocalGroups)
            active_directory_users = @($ADUsers)
            domain_admins_members  = @($DomainAdminsMembers)
        }
        access_inventory = [ordered]@{
            smb_shares = @($SMBShares)
        }
        statistics = [ordered]@{
            local_user_count            = @($LocalUsers).Count
            local_group_count           = @($LocalGroups).Count
            active_directory_user_count = @($ADUsers).Count
            domain_admins_member_count  = @($DomainAdminsMembers).Count
            smb_share_count             = @($SMBShares).Count
        }
    }

    return $Inventory
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $Inventory = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $Inventory = & $AccessModelingScriptBlock
        }
        else {
            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $AccessModelingScriptBlock `
                -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[-] Current user context failed for $Target. Requesting credentials..." -ForegroundColor DarkGray
    }

    if ($null -eq $Inventory -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target

            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $AccessModelingScriptBlock `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $Inventory -and $IsLocalTarget) {
        Write-Host "[!] Failed to collect local inventory from ${Target}." -ForegroundColor Red
        continue
    }

    try {
        if ($Inventory.hostname) {
            $FinalHostName = $Inventory.hostname
        }

        $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
        $OutputFilePath = Join-Path -Path $OutputDir -ChildPath "${SafeHostName}-access-modeling-results.json"

        $Inventory |
            ConvertTo-Json -Depth 8 |
            Set-Content -Path $OutputFilePath -Encoding UTF8 -Force

        $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

        Write-Host "[+] Access Modeling inventory saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
        Write-Host "[+] Local users: $($Inventory.statistics.local_user_count)" -ForegroundColor Gray
        Write-Host "[+] Local groups: $($Inventory.statistics.local_group_count)" -ForegroundColor Gray
        Write-Host "[+] Active Directory users: $($Inventory.statistics.active_directory_user_count)" -ForegroundColor Gray
        Write-Host "[+] Domain Admins members: $($Inventory.statistics.domain_admins_member_count)" -ForegroundColor Gray
        Write-Host "[+] SMB shares: $($Inventory.statistics.smb_share_count)" -ForegroundColor Gray
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
notepad access-modeling.ps1
.\access-modeling.ps1 # Local Inventory
.\access-modeling.ps1 WIN-E31P99E3C3J # Remote Inventory via WinRM
```

### Local & Remote Windows Access Control List Inventory

#### [Powershell](https://github.com/powershell/powershell)

{% hint style="info" %}
View ACLs for all files or directories of your desired path:
{% endhint %}

```powershell
<#
.SYNOPSIS
    Windows Path ACL Inventory Script.

.DESCRIPTION
    Collects ACL information for files under a user-specified path on local or remote Windows hosts.
    Writes one JSON file per host into inventory_results.

.OUTPUT
    inventory_results\<hostname>-<path>-ACL-results.json
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Targets,

    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'
$OutputDir = 'inventory_results'

function Normalize-PathString {
    param([Parameter(Mandatory = $true)][string]$InputPath)
    $p = $InputPath.Trim()
    $p = $p.Trim('"').Trim("'")
    return $p
}

function Convert-PathToSafeName {
    param([Parameter(Mandatory = $true)][string]$InputPath)

    $Safe = $InputPath -replace '[:\\\/]+', '-'
    $Safe = $Safe -replace '-{2,}', '-'
    $Safe = $Safe.Trim('-')
    return $Safe
}

function Test-LocalTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $NormalizedTarget = $Target.Trim().ToLowerInvariant()
    $LocalComputerName = $env:COMPUTERNAME.ToLowerInvariant()

    if ($NormalizedTarget -eq 'localhost') { return $true }
    if ($NormalizedTarget -eq '.') { return $true }
    if ($NormalizedTarget -eq $LocalComputerName) { return $true }

    return $false
}

function Read-CliCredentialForTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Write-Host "`n[!] Credentials required for $Target" -ForegroundColor Yellow
    $UserName = Read-Host "Username for $Target (Format: DOMAIN\User or $Target\User)"
    $Password = Read-Host "Password for $Target" -AsSecureString
    return [pscredential]::new($UserName, $Password)
}

$Path = Normalize-PathString -InputPath $Path

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($Targets)) {
    $ComputerNames = @('localhost')
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

$AclInventoryScriptBlock = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScanPath
    )

    $ErrorActionPreference = 'Stop'
    $Hostname = $env:COMPUTERNAME
    $Timestamp = (Get-Date).ToString('o')

    $Items = @()
    $EnumerationErrors = @()

    function Normalize-PathString {
        param([Parameter(Mandatory = $true)][string]$InputPath)
        $p = $InputPath.Trim()
        $p = $p.Trim('"').Trim("'")
        return $p
    }

    function Convert-FileAclToObject {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath
        )

        $Acl = Get-Acl -LiteralPath $FilePath -ErrorAction Stop
        $Item = Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop

        $AccessEntries = @(
            foreach ($Rule in $Acl.Access) {
                [ordered]@{
                    IdentityReference = [string]$Rule.IdentityReference
                    FileSystemRights  = [string]$Rule.FileSystemRights
                    AccessControlType = [string]$Rule.AccessControlType
                    IsInherited       = [bool]$Rule.IsInherited
                    InheritanceFlags  = [string]$Rule.InheritanceFlags
                    PropagationFlags  = [string]$Rule.PropagationFlags
                }
            }
        )

        [ordered]@{
            hostname   = [string]$Hostname
            asset_type = 'filesystem_file'
            path       = [string]$Item.FullName
            owner      = [string]$Acl.Owner
            access     = $AccessEntries
            size_bytes = [int64]$Item.Length
            mtime      = $Item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    $ScanPath = Normalize-PathString -InputPath $ScanPath

    try {
        $ResolvedPath = (Resolve-Path -LiteralPath $ScanPath -ErrorAction Stop).Path
        $RootItem = Get-Item -LiteralPath $ResolvedPath -Force -ErrorAction Stop
    }
    catch {
        return [ordered]@{
            hostname        = $Hostname
            collection_time = $Timestamp
            target_path     = $ScanPath
            resolved_path   = $null
            files           = @()
            statistics      = [ordered]@{
                file_count              = 0
                enumerated_item_count    = 0
                enumeration_error_count  = 0
            }
            error = "Path cannot be resolved: $($_.Exception.Message)"
        }
    }

    if (-not $RootItem.PSIsContainer) {
        try {
            $Items += ,(Convert-FileAclToObject -FilePath $RootItem.FullName)
        }
        catch {
            $EnumerationErrors += ,[ordered]@{
                stage   = 'Get-Acl'
                path    = $RootItem.FullName
                message = $_.Exception.Message
            }
        }

        return [ordered]@{
            hostname        = $Hostname
            collection_time = $Timestamp
            target_path     = $ScanPath
            resolved_path   = $ResolvedPath
            files           = @($Items)
            statistics      = [ordered]@{
                file_count              = @($Items).Count
                enumerated_item_count    = 1
                enumeration_error_count  = @($EnumerationErrors).Count
            }
            enumeration_errors = @($EnumerationErrors)
        }
    }

    $AllFiles = @()
    try {
        $AllFiles = @(
            Get-ChildItem -LiteralPath $ResolvedPath -File -Recurse -Force -ErrorAction Stop
        )
    }
    catch {
        $EnumerationErrors += ,[ordered]@{
            stage   = 'Get-ChildItem'
            path    = $ResolvedPath
            message = $_.Exception.Message
        }
    }

    foreach ($File in $AllFiles) {
        try {
            $Items += ,(Convert-FileAclToObject -FilePath $File.FullName)
        }
        catch {
            $EnumerationErrors += ,[ordered]@{
                stage   = 'Get-Acl'
                path    = $File.FullName
                message = $_.Exception.Message
            }
        }
    }

    [ordered]@{
        hostname        = $Hostname
        collection_time = $Timestamp
        target_path     = $ScanPath
        resolved_path   = $ResolvedPath
        files           = @($Items)
        statistics      = [ordered]@{
            file_count              = @($Items).Count
            enumerated_item_count   = @($AllFiles).Count
            enumeration_error_count = @($EnumerationErrors).Count
        }
        enumeration_errors = @($EnumerationErrors)
    }
}

foreach ($Target in $ComputerNames) {
    Write-Host "`n[?] Processing Host: $Target" -ForegroundColor Cyan

    $Inventory = $null
    $FinalHostName = $Target
    $IsLocalTarget = Test-LocalTarget -Target $Target

    try {
        if ($IsLocalTarget) {
            $Inventory = & $AclInventoryScriptBlock -ScanPath $Path
        }
        else {
            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $AclInventoryScriptBlock `
                -ArgumentList $Path `
                -ErrorAction Stop
        }
    }
    catch {
        if ($IsLocalTarget) {
            Write-Host "[!] Local collection error for ${Target}: $($_.Exception.Message)" -ForegroundColor Red
        }
        else {
            Write-Host "[-] Current user context failed for $Target. Requesting credentials..." -ForegroundColor DarkGray
        }
    }

    if ($null -eq $Inventory -and -not $IsLocalTarget) {
        try {
            $Credential = Read-CliCredentialForTarget -Target $Target
            $Inventory = Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock $AclInventoryScriptBlock `
                -ArgumentList $Path `
                -Credential $Credential `
                -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Failed to collect from ${Target}: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    if ($null -eq $Inventory) {
        Write-Host "[!] Failed to collect inventory from ${Target}." -ForegroundColor Red
        continue
    }

    try {
        if ($Inventory.hostname) {
            $FinalHostName = $Inventory.hostname
        }

        $SafeHostName = $FinalHostName -replace '[\\/:*?"<>|]', '_'
        $SafePathName  = Convert-PathToSafeName -InputPath $Inventory.target_path
        $OutputFileName = "${SafeHostName}-${SafePathName}-ACL-results.json"
        $OutputFilePath = Join-Path -Path $OutputDir -ChildPath $OutputFileName

        $Inventory |
            ConvertTo-Json -Depth 10 |
            Set-Content -Path $OutputFilePath -Encoding UTF8 -Force

        $FullOutputPath = (Get-Item -Path $OutputFilePath).FullName

        Write-Host "[+] ACL inventory saved for ${FinalHostName}: $FullOutputPath" -ForegroundColor Green
        Write-Host "[+] Resolved path: $($Inventory.resolved_path)" -ForegroundColor Gray
        Write-Host "[+] Enumerated items: $($Inventory.statistics.enumerated_item_count)" -ForegroundColor Gray
        Write-Host "[+] Files collected: $($Inventory.statistics.file_count)" -ForegroundColor Gray
        Write-Host "[+] Enumeration errors: $($Inventory.statistics.enumeration_error_count)" -ForegroundColor Gray
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
notepad windows-acl-inventory.ps1
.\windows-acl-inventory.ps1 "C:\Path" # Local Inventory
.\windows-acl-inventory.ps1 WIN-E31P99E3C3J -Path "C:\Path" # Remote Inventory via WinRM
```

### Local & Remote Linux Access Modeling

#### [getent](https://man7.org/linux/man-pages/man1/getent.1.html) & [groups](https://man7.org/linux/man-pages/man1/groups.1.html) & [jq](https://jqlang.org/)

{% hint style="info" %}
Collect user and group records
{% endhint %}

```bash
#!/usr/bin/env bash
set -euo pipefail

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local directory: $LOCAL_DIR" >&2
    exit 1
}

run_access_modeling_block() {
    inventory_hostname="$1"
    output_file="$2"

    echo "[+] Access Modeling collection started." >&2
    echo "[+] Inventory hostname: $inventory_hostname" >&2
    echo "[+] Output file: $output_file" >&2

    temporary_directory="$(mktemp -d)" || {
        echo "[ERROR] Failed to create a temporary directory." >&2
        return 10
    }

    passwd_jsonl="${temporary_directory}/passwd.jsonl"
    group_jsonl="${temporary_directory}/group.jsonl"
    users_json="${temporary_directory}/users.json"
    groups_json="${temporary_directory}/groups.json"
    temporary_output="${temporary_directory}/result.json"

    cleanup_collection_files() {
        rm -rf -- "$temporary_directory"
    }

    trap cleanup_collection_files RETURN

    : > "$passwd_jsonl"
    : > "$group_jsonl"

    echo "[*] Collecting user identities with getent passwd ..." >&2

    while IFS=: read -r username password uid gid gecos home shell; do
        if ! jq -nc \
            --arg username "$username" \
            --arg password_field "$password" \
            --arg uid "$uid" \
            --arg gid "$gid" \
            --arg gecos "$gecos" \
            --arg home_directory "$home" \
            --arg login_shell "$shell" \
            '{
                username: $username,
                password_field: $password_field,
                uid: ($uid | tonumber),
                gid: ($gid | tonumber),
                gecos: $gecos,
                home_directory: $home_directory,
                login_shell: $login_shell
            }' >> "$passwd_jsonl"
        then
            echo "[ERROR] Failed to serialize user: $username" >&2
            return 11
        fi
    done < <(getent passwd)

    echo "[*] Collecting group identities with getent group ..." >&2

    while IFS=: read -r group_name password gid members; do
        if ! jq -nc \
            --arg group_name "$group_name" \
            --arg password_field "$password" \
            --arg gid "$gid" \
            --arg members "$members" \
            '{
                group_name: $group_name,
                password_field: $password_field,
                gid: ($gid | tonumber),
                members: (
                    if $members == "" then
                        []
                    else
                        ($members | split(","))
                    end
                )
            }' >> "$group_jsonl"
        then
            echo "[ERROR] Failed to serialize group: $group_name" >&2
            return 12
        fi
    done < <(getent group)

    jq -s '.' "$passwd_jsonl" > "$users_json" || {
        echo "[ERROR] Failed to create the users JSON array." >&2
        return 13
    }

    jq -s '.' "$group_jsonl" > "$groups_json" || {
        echo "[ERROR] Failed to create the groups JSON array." >&2
        return 14
    }

    collection_time="$(date -Iseconds 2>/dev/null || date)"

    jq -n \
        --arg hostname "$inventory_hostname" \
        --arg collection_time "$collection_time" \
        --slurpfile users "$users_json" \
        --slurpfile groups "$groups_json" \
        '{
            hostname: $hostname,
            collection_time: $collection_time,
            commands: {
                passwd: "getent passwd",
                group: "getent group"
            },
            identity_inventory: {
                users: $users[0],
                groups: $groups[0]
            },
            statistics: {
                user_count: ($users[0] | length),
                group_count: ($groups[0] | length)
            }
        }' > "$temporary_output" || {
            echo "[ERROR] Failed to create the final JSON document." >&2
            return 15
        }

    if ! jq -e '.' "$temporary_output" >/dev/null 2>&1; then
        echo "[ERROR] The generated inventory is not valid JSON." >&2
        return 16
    fi

    if ! mv -- "$temporary_output" "$output_file"; then
        echo "[ERROR] Failed to write output file: $output_file" >&2
        return 17
    fi

    user_count="$(wc -l < "$passwd_jsonl" | tr -d '[:space:]')"
    group_count="$(wc -l < "$group_jsonl" | tr -d '[:space:]')"

    echo "[+] Access Modeling collection completed." >&2
    echo "[+] Users collected: $user_count" >&2
    echo "[+] Groups collected: $group_count" >&2
    echo "[+] Inventory file: $output_file" >&2
}

check_dependencies() {
    missing=0

    for command_name in bash getent jq hostname date mktemp mv rm wc tr; do
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

if [ "$#" -eq 0 ]; then
    echo "[*] Running in local mode ..."
    echo "[*] Checking local dependencies ..."

    if ! check_dependencies; then
        echo "[ERROR] Required commands are unavailable." >&2
        echo "[INFO] Debian or Ubuntu installation command:" >&2
        echo "       sudo apt update && sudo apt install jq libc-bin coreutils" >&2
        exit 1
    fi

    LOCAL_HOSTNAME="$(
        hostname -s 2>/dev/null ||
        hostname 2>/dev/null ||
        printf '%s\n' "unknown-host"
    )"

    LOCAL_HOSTNAME="$(printf '%s' "$LOCAL_HOSTNAME" | tr -d '\r\n')"
    SAFE_HOSTNAME="$(make_safe_hostname "$LOCAL_HOSTNAME")"

    if [ -z "$SAFE_HOSTNAME" ]; then
        SAFE_HOSTNAME="unknown-host"
    fi

    LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-access-modeling-results.json"

    echo "[+] Local hostname: $LOCAL_HOSTNAME"
    echo "[+] Local output file: $LOCAL_FILE"

    run_access_modeling_block "$LOCAL_HOSTNAME" "$LOCAL_FILE"

    echo "[+] Access Modeling inventory complete."
    echo "[+] Saved to: $LOCAL_FILE"
    exit 0
fi

TARGET="$1"

if ! command -v ssh >/dev/null 2>&1 ||
   ! command -v scp >/dev/null 2>&1; then
    echo "[ERROR] Local ssh and scp commands are required." >&2
    exit 1
fi

CONTROL_DIR="$(mktemp -d)" || {
    echo "[ERROR] Failed to create the SSH control directory." >&2
    exit 1
}

CONTROL_PATH="${CONTROL_DIR}/ssh-control-%C"

SSH_OPTS=(
    -o ControlMaster=auto
    -o ControlPath="$CONTROL_PATH"
    -o ControlPersist=10m
)

cleanup_ssh_control() {
    ssh "${SSH_OPTS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
    rm -rf -- "$CONTROL_DIR"
}

trap cleanup_ssh_control EXIT

echo "[*] Running in remote mode ..."
echo "[*] Testing SSH connection to: $TARGET"

if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 "$TARGET" \
    'printf "[+] SSH connection established on: %s\n" "$(hostname)"'
then
    echo "[ERROR] SSH connection failed: $TARGET" >&2
    exit 1
fi

echo "[*] Checking remote dependencies ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" '
    missing=0

    for command_name in bash getent jq hostname date mktemp mv rm wc tr; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing remote dependency: $command_name" >&2
            missing=1
        fi
    done

    exit "$missing"
'
then
    echo "[ERROR] Required commands are unavailable on the remote host." >&2
    echo "[INFO] Debian or Ubuntu installation command:" >&2
    echo "       sudo apt update && sudo apt install jq libc-bin coreutils" >&2
    exit 1
fi

echo "[*] Retrieving remote hostname ..."

REMOTE_HOSTNAME="$(
    ssh "${SSH_OPTS[@]}" "$TARGET" \
        'hostname -s 2>/dev/null || hostname 2>/dev/null || printf "%s\n" unknown-host'
)" || {
    echo "[ERROR] Failed to retrieve the remote hostname." >&2
    exit 1
}

REMOTE_HOSTNAME="$(printf '%s' "$REMOTE_HOSTNAME" | tr -d '\r\n')"

if [ -z "$REMOTE_HOSTNAME" ]; then
    echo "[ERROR] Remote hostname is empty." >&2
    exit 1
fi

SAFE_HOSTNAME="$(make_safe_hostname "$REMOTE_HOSTNAME")"

if [ -z "$SAFE_HOSTNAME" ]; then
    SAFE_HOSTNAME="unknown-host"
fi

REMOTE_FILE="/tmp/${SAFE_HOSTNAME}-access-modeling-results.json"
LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-access-modeling-results.json"

echo "[+] Remote hostname: $REMOTE_HOSTNAME"
echo "[+] Remote output file: $REMOTE_FILE"
echo "[+] Local output file: $LOCAL_FILE"
echo "[*] Starting remote Access Modeling collection ..."

{
    printf '%s\n' 'set -euo pipefail'
    declare -f run_access_modeling_block
    printf '%s\n' 'run_access_modeling_block "$1" "$2"'
} | ssh "${SSH_OPTS[@]}" "$TARGET" \
    bash -s -- "$REMOTE_HOSTNAME" "$REMOTE_FILE"

SSH_EXIT=$?

if [ "$SSH_EXIT" -ne 0 ]; then
    echo "[ERROR] Remote Access Modeling collection failed." >&2
    echo "[ERROR] SSH exit code: $SSH_EXIT" >&2
    exit 1
fi

echo "[*] Verifying remote inventory file ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" \
    "test -s '$REMOTE_FILE' && jq -e '.' '$REMOTE_FILE' >/dev/null 2>&1"
then
    echo "[ERROR] Remote inventory is missing, empty, or invalid." >&2
    exit 1
fi

echo "[*] Retrieving remote inventory ..."

if ! scp "${SSH_OPTS[@]}" -- "$TARGET:$REMOTE_FILE" "$LOCAL_FILE"; then
    echo "[ERROR] Failed to retrieve remote inventory: $REMOTE_FILE" >&2
    exit 1
fi

if [ ! -s "$LOCAL_FILE" ]; then
    echo "[ERROR] Retrieved inventory is empty or missing: $LOCAL_FILE" >&2
    exit 1
fi

if ! jq -e '.' "$LOCAL_FILE" >/dev/null 2>&1; then
    echo "[ERROR] Retrieved inventory is not valid JSON: $LOCAL_FILE" >&2
    exit 1
fi

USER_COUNT="$(jq '.statistics.user_count' "$LOCAL_FILE")"
GROUP_COUNT="$(jq '.statistics.group_count' "$LOCAL_FILE")"

echo "[+] Inventory retrieved successfully."
echo "[+] Users collected: $USER_COUNT"
echo "[+] Groups collected: $GROUP_COUNT"

echo "[*] Removing remote inventory file ..."

if ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f -- '$REMOTE_FILE'"; then
    echo "[+] Remote inventory file removed."
else
    echo "[WARNING] Failed to remove remote file: $REMOTE_FILE" >&2
fi

echo "[+] Access Modeling inventory complete."
echo "[+] Saved to: $LOCAL_FILE"
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
sudo chmod +x access-modeling.sh
sudo ./access-modeling.sh # Local Inventory
sudo ./access-modeling.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

### Local & Remote Linux Access Control List Inventory

#### [getfacl](https://man7.org/linux/man-pages/man1/getfacl.1.html) & [jq](https://jqlang.org/)

{% hint style="info" %}
Collect Linux filesystem ACL metadata including file or directory paths, owners, groups, and ACL permission entries
{% endhint %}

```bash
#!/bin/bash

LOCAL_DIR="./inventory_results"

mkdir -p "$LOCAL_DIR" || {
    echo "[ERROR] Failed to create local directory: $LOCAL_DIR" >&2
    exit 1
}

normalize_input_path() {
    input_path="$1"
    input_path="$(printf '%s' "$input_path" | tr -d '\r\n')"
    input_path="${input_path#\"}"
    input_path="${input_path%\"}"
    input_path="${input_path#\'}"
    input_path="${input_path%\'}"
    printf '%s' "$input_path"
}

make_safe_hostname() {
    printf '%s' "$1" |
        tr -d '\r\n' |
        sed 's/[^A-Za-z0-9._-]/_/g'
}

make_safe_path_name() {
    input_path="$1"

    input_path="$(normalize_input_path "$input_path")"

    printf '%s' "$input_path" |
        sed 's#^[[:space:]]*##; s#[[:space:]]*$##' |
        sed 's#^/*##' |
        sed 's#/*$##' |
        sed 's#[/\\:]#-#g' |
        sed 's#-\{2,\}#-#g' |
        sed 's#^-##; s#-$##'
}

run_acl_inventory_block() {
    inventory_hostname="$1"
    target_path="$2"
    output_file="$3"

    echo "[+] ACL inventory command block started." >&2
    echo "[+] Inventory hostname: $inventory_hostname" >&2
    echo "[+] Target path: $target_path" >&2
    echo "[+] Writing inventory to: $output_file" >&2

    if ! : > "$output_file"; then
        echo "[ERROR] Cannot create output file: $output_file" >&2
        exit 10
    fi

    normalized_path="$(normalize_input_path "$target_path")"

    if [ -z "$normalized_path" ]; then
        echo "[ERROR] Target path is empty after normalization." >&2
        exit 11
    fi

    if [ ! -e "$normalized_path" ]; then
        echo "[ERROR] Target path does not exist: $normalized_path" >&2
        exit 12
    fi

    collection_time="$(date -Iseconds 2>/dev/null || date)"
    tmp_acl_file="$(mktemp)" || {
        echo "[ERROR] Failed to create temporary ACL file." >&2
        exit 13
    }

    cleanup_tmp_acl() {
        rm -f "$tmp_acl_file"
    }

    trap cleanup_tmp_acl RETURN

    echo "[*] Running getfacl -R against: $normalized_path" >&2

    if ! getfacl -R -p --absolute-names "$normalized_path" > "$tmp_acl_file" 2>/dev/null; then
        echo "[ERROR] getfacl failed for path: $normalized_path" >&2
        exit 14
    fi

    if [ ! -s "$tmp_acl_file" ]; then
        echo "[ERROR] getfacl produced no output for path: $normalized_path" >&2
        exit 15
    fi

    jq -Rs \
        --arg hostname "$inventory_hostname" \
        --arg asset_type "filesystem_acl" \
        --arg target_path "$normalized_path" \
        --arg collection_time "$collection_time" \
        '
        def parse_acl_blocks:
            split("\n\n")
            | map(select(length > 0))
            | map(
                split("\n") as $lines
                | {
                    raw_lines: $lines,
                    path: (
                        $lines
                        | map(select(startswith("# file: ")))
                        | .[0]
                        | sub("^# file: "; "")
                    ),
                    owner: (
                        $lines
                        | map(select(startswith("# owner: ")))
                        | .[0]?
                        | if . == null then null else sub("^# owner: "; "") end
                    ),
                    group: (
                        $lines
                        | map(select(startswith("# group: ")))
                        | .[0]?
                        | if . == null then null else sub("^# group: "; "") end
                    ),
                    acl_entries: (
                        $lines
                        | map(
                            select(
                                (startswith("#") | not)
                                and (length > 0)
                            )
                        )
                    )
                }
                | select(.path != null and .path != "")
            );

        {
            hostname: $hostname,
            asset_type: $asset_type,
            target_path: $target_path,
            collection_time: $collection_time,
            acl_objects: (
                parse_acl_blocks
                | map(
                    {
                        hostname: $hostname,
                        asset_type: $asset_type,
                        path: .path,
                        owner: .owner,
                        group: .group,
                        acl_entries: .acl_entries
                    }
                )
            )
        }
        ' < "$tmp_acl_file" > "$output_file"

    if [ $? -ne 0 ]; then
        echo "[ERROR] jq failed while converting ACL output to JSON." >&2
        exit 16
    fi

    if [ ! -s "$output_file" ]; then
        echo "[ERROR] Output file is empty: $output_file" >&2
        exit 17
    fi

    record_count="$(
        jq '.acl_objects | length' "$output_file" 2>/dev/null ||
            echo 0
    )"

    echo "[+] getfacl scan completed." >&2
    echo "[+] ACL object count: $record_count" >&2
    echo "[+] Inventory file: $output_file" >&2

    exit 0
}

check_dependencies() {
    missing=0

    for command_name in bash getfacl jq hostname wc sed tr mktemp date; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "[ERROR] Missing dependency: $command_name" >&2
            missing=1
        fi
    done

    return "$missing"
}

if [ $# -eq 0 ]; then
    echo "[ERROR] Missing path argument." >&2
    echo "[USAGE] $0 \"path/to/target\"" >&2
    echo "[USAGE] $0 user@host \"path/to/target\"" >&2
    exit 1
fi

if [ $# -eq 1 ]; then
    MODE="local"
    TARGET_PATH="$1"
else
    MODE="remote"
    TARGET="$1"
    TARGET_PATH="$2"
fi

TARGET_PATH="$(normalize_input_path "$TARGET_PATH")"

if [ -z "$TARGET_PATH" ]; then
    echo "[ERROR] Provided path is empty." >&2
    exit 1
fi

SAFE_PATH_NAME="$(make_safe_path_name "$TARGET_PATH")"

if [ -z "$SAFE_PATH_NAME" ]; then
    echo "[ERROR] Failed to derive safe path name from: $TARGET_PATH" >&2
    exit 1
fi

if [ "$MODE" = "local" ]; then
    echo "[*] Running in local mode ..."
    echo "[*] Checking local dependencies ..."

    if ! check_dependencies; then
        echo "[ERROR] One or more required commands are not available on the local host." >&2
        echo "[INFO] On Debian or Ubuntu, install them with:" >&2
        echo "       sudo apt update && sudo apt install acl jq coreutils sed" >&2
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

    LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-${SAFE_PATH_NAME}-ACL-results.json"

    echo "[+] Local hostname: $LOCAL_HOSTNAME"
    echo "[+] Local output file: $LOCAL_FILE"
    echo "[*] Starting local ACL inventory ..."

    run_acl_inventory_block "$LOCAL_HOSTNAME" "$TARGET_PATH" "$LOCAL_FILE"
    exit $?
fi

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

    for command_name in bash getfacl jq hostname wc sed tr mktemp date; do
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
    echo "       sudo apt update && sudo apt install acl jq coreutils sed" >&2
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

REMOTE_FILE="/tmp/${SAFE_HOSTNAME}-${SAFE_PATH_NAME}-ACL-results.json"
LOCAL_FILE="${LOCAL_DIR}/${SAFE_HOSTNAME}-${SAFE_PATH_NAME}-ACL-results.json"

echo "[+] Remote hostname: $REMOTE_HOSTNAME"
echo "[+] Remote output file: $REMOTE_FILE"
echo "[+] Local output file: $LOCAL_FILE"
echo "[*] Starting remote ACL inventory ..."

{
    declare -f normalize_input_path
    declare -f run_acl_inventory_block
    printf 'run_acl_inventory_block "$1" "$2" "$3"\n'
} | ssh "${SSH_OPTS[@]}" "$TARGET" bash -s -- "$REMOTE_HOSTNAME" "$TARGET_PATH" "$REMOTE_FILE"

SSH_EXIT=$?

if [ "$SSH_EXIT" -ne 0 ]; then
    echo "[ERROR] Remote ACL inventory command failed." >&2
    echo "[ERROR] SSH exit code: $SSH_EXIT" >&2
    echo "[INFO] The script will not continue to scp." >&2
    exit 1
fi

echo "[+] Remote ACL inventory command completed successfully."
echo "[*] Verifying remote inventory file ..."

if ! ssh "${SSH_OPTS[@]}" "$TARGET" "test -s '$REMOTE_FILE'"; then
    echo "[ERROR] Remote inventory file is missing or empty: $REMOTE_FILE" >&2
    exit 1
fi

echo "[*] Retrieving $(basename "$LOCAL_FILE") ..."

if ! scp "${SSH_OPTS[@]}" -- "$TARGET:$REMOTE_FILE" "$LOCAL_FILE"; then
    echo "[ERROR] scp failed while retrieving: $REMOTE_FILE" >&2
    exit 1
fi

if [ ! -s "$LOCAL_FILE" ]; then
    echo "[ERROR] Retrieved file is empty or missing: $LOCAL_FILE" >&2
    exit 1
fi

LOCAL_RECORD_COUNT="$(
    jq '.acl_objects | length' "$LOCAL_FILE" 2>/dev/null ||
        echo 0
)"

echo "[+] ACL inventory file retrieved successfully."
echo "[+] Local ACL object count: $LOCAL_RECORD_COUNT"

echo "[*] Cleaning up remote inventory file ..."

if ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f -- '$REMOTE_FILE'"; then
    echo "[+] Remote inventory file removed."
else
    echo "[WARNING] Could not remove remote file: $REMOTE_FILE" >&2
fi

echo "[+] ACL inventory complete."
echo "[+] Saved to: $LOCAL_FILE"
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
sudo chmod +x linux-acl-inventory.sh
sudo ./linux-acl-inventory.sh # Local Inventory
sudo ./linux-acl-inventory.sh ubuntu-clone@192.168.109.150 # Remote Inventory via SSH
```

{% hint style="info" %}
Inspect sudoers file (requires root access)
{% endhint %}

```bash
cat /etc/sudoers
```

{% hint style="info" %}
Check included configs
{% endhint %}

```bash
ls -l /etc/sudoers.d/
```
