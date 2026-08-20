# Network Node Inventory

## Cheat Sheet

### Inventory using Linux

#### [Nmap](https://github.com/nmap/nmap) & [snmpwalk](https://github.com/nmap/nmap)

{% hint style="info" %}
Gather IP Address, Mac Address, Hostname, Vendor, OS, Interface, Subnet, Gateway, Management Protocol, Running Services, HTTP Title, SSH Banner, Open Ports & Local LLDP Information
{% endhint %}

```bash
#!/usr/bin/env bash

set -u
set -o pipefail

TARGET_FILE="${1:-targets.txt}"
SCRIPT_NAME="$(basename "$0")"
TMP_DIR="$(mktemp -d)"
DATE_NOW="$(date '+%Y-%m-%d %H:%M:%S %Z')"

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
OUTPUT_DIR="$REAL_HOME/network_node_inventory"
OUTPUT_FILE="$OUTPUT_DIR/inventory_report.txt"
SNMP_COMMUNITY="public"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

print_usage() {
    echo "Usage: sudo ./$SCRIPT_NAME targets.txt"
    echo
    echo "Output:"
    echo "  $OUTPUT_FILE"
}

prompt_snmp_community() {
    local input=""

    printf "Enter SNMP community string [or press Enter for public]: "
    read -r input

    if [ -n "$input" ]; then
        SNMP_COMMUNITY="$input"
    fi
}

prepare_output_dir() {
    mkdir -p "$OUTPUT_DIR" || {
        echo "Failed to create output directory: $OUTPUT_DIR" >&2
        exit 1
    }

    if [ -n "${SUDO_USER:-}" ]; then
        chown "$REAL_USER":"$REAL_USER" "$OUTPUT_DIR" 2>/dev/null || true
    fi
}

finalize_output_permissions() {
    if [ -n "${SUDO_USER:-}" ] && [ -f "$OUTPUT_FILE" ]; then
        chown "$REAL_USER":"$REAL_USER" "$OUTPUT_FILE" 2>/dev/null || true
    fi
}

get_dns_name() {
    local ip="$1"

    if require_cmd host; then
        host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF}' | sed 's/\.$//' | head -n1
    elif require_cmd dig; then
        dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -n1
    fi
}

get_route_field() {
    local ip="$1"
    local field="$2"

    ip route get "$ip" 2>/dev/null | awk -v field="$field" '
    {
        for (i = 1; i <= NF; i++) {
            if ($i == field) {
                print $(i + 1)
                exit
            }
        }
    }'
}

get_interface_for_ip() {
    local ip="$1"
    get_route_field "$ip" "dev"
}

get_gateway_for_ip() {
    local ip="$1"
    get_route_field "$ip" "via"
}

get_source_ip_for_target() {
    local ip="$1"
    get_route_field "$ip" "src"
}

get_subnet_for_interface() {
    local iface="$1"

    if [ -n "$iface" ]; then
        ip -o -f inet addr show "$iface" 2>/dev/null | awk '{print $4}' | head -n1
    fi
}

get_mac_vendor_by_nmap() {
    local ip="$1"

    nmap -sn "$ip" 2>/dev/null | awk '
    /MAC Address:/ {
        mac = $3
        vendor = ""
        if (index($0, "(") > 0) {
            vendor = $0
            sub(/^.*\(/, "", vendor)
            sub(/\).*$/, "", vendor)
        }
        print mac "|" vendor
        exit
    }'
}

get_mac_from_ip_neigh() {
    local ip="$1"

    ip neigh show "$ip" 2>/dev/null | awk '
    {
        for (i = 1; i <= NF; i++) {
            if ($i == "lladdr") {
                print $(i + 1)
                exit
            }
        }
    }'
}

get_service_summary() {
    local ip="$1"

    nmap -Pn -sV --top-ports 50 "$ip" 2>/dev/null | awk '
    /^[0-9]+\/tcp[[:space:]]+open/ || /^[0-9]+\/udp[[:space:]]+open/ {
        port = $1
        state = $2
        service = $3
        version = ""
        for (i = 4; i <= NF; i++) {
            version = version $i " "
        }
        sub(/[[:space:]]+$/, "", version)
        print port " " state " " service " " version
    }'
}

get_snmp_sysname() {
    local ip="$1"

    if require_cmd snmpwalk; then
        snmpwalk -v2c -c "$SNMP_COMMUNITY" -t 1 -r 0 "$ip" 1.3.6.1.2.1.1.5.0 2>/dev/null |
            sed 's/^.*STRING: //' | head -n1
    fi
}

get_snmp_sysdescr() {
    local ip="$1"

    if require_cmd snmpwalk; then
        snmpwalk -v2c -c "$SNMP_COMMUNITY" -t 1 -r 0 "$ip" 1.3.6.1.2.1.1.1.0 2>/dev/null |
            sed 's/^.*STRING: //' | head -n1
    fi
}

get_ssh_banner() {
    local ip="$1"

    if require_cmd timeout; then
        timeout 2 bash -c "exec 3<>/dev/tcp/$ip/22; head -n 1 <&3" 2>/dev/null | tr -d '\r'
    fi
}

get_http_title() {
    local ip="$1"

    if require_cmd curl; then
        {
            curl -k -L -m 2 -s "http://$ip" 2>/dev/null
            curl -k -L -m 2 -s "https://$ip" 2>/dev/null
        } | awk -F'[<>]' 'tolower($0) ~ /<title>/ {gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3; exit}'
    fi
}

write_header() {
    cat > "$OUTPUT_FILE" <<EOF_REPORT
Network Node Inventory Report
Generated: $DATE_NOW
Target File: $TARGET_FILE
Output File: $OUTPUT_FILE

EOF_REPORT
}

discover_live_hosts() {
    local live_file="$1"

    nmap -sn -iL "$TARGET_FILE" -oG - 2>/dev/null | awk '
    /Status: Up/ {
        print $2
    }' | sort -u > "$live_file"
}

write_record() {
    local ip="$1"

    local dns_name
    local iface
    local gateway
    local src_ip
    local subnet
    local mac_vendor
    local mac
    local vendor
    local snmp_name
    local snmp_descr
    local ssh_banner
    local http_title
    local services_file
    local ports_file
    local management_protocols
    local safe_ip

    safe_ip="$(echo "$ip" | sed 's#[^A-Za-z0-9_.-]#_#g')"
    services_file="$TMP_DIR/${safe_ip}_services.txt"
    ports_file="$TMP_DIR/${safe_ip}_ports.txt"

    dns_name="$(get_dns_name "$ip")"
    iface="$(get_interface_for_ip "$ip")"
    gateway="$(get_gateway_for_ip "$ip")"
    src_ip="$(get_source_ip_for_target "$ip")"
    subnet="$(get_subnet_for_interface "$iface")"

    mac_vendor="$(get_mac_vendor_by_nmap "$ip")"
    mac="$(echo "$mac_vendor" | awk -F'|' '{print $1}')"
    vendor="$(echo "$mac_vendor" | awk -F'|' '{print $2}')"

    if [ -z "$mac" ]; then
        mac="$(get_mac_from_ip_neigh "$ip")"
    fi

    mac="$(echo "$mac" | tr '[:lower:]' '[:upper:]')"

    get_service_summary "$ip" > "$services_file"
    awk '{print $1}' "$services_file" > "$ports_file"

    snmp_name="$(get_snmp_sysname "$ip")"
    snmp_descr="$(get_snmp_sysdescr "$ip")"
    ssh_banner="$(get_ssh_banner "$ip")"
    http_title="$(get_http_title "$ip")"

    management_protocols="$(awk '
    /^22\/tcp/ {print "22/tcp"}
    /^80\/tcp/ {print "80/tcp"}
    /^443\/tcp/ {print "443/tcp"}
    /^3389\/tcp/ {print "3389/tcp"}
    /^5985\/tcp/ {print "5985/tcp"}
    /^5986\/tcp/ {print "5986/tcp"}
    /^161\/udp/ {print "161/udp"}
    ' "$services_file" | sort -u | paste -sd "," -)"

    {
        echo "IP Address: $ip"
        echo "MAC Address: ${mac:-N/A}"
        echo "Hostname: ${dns_name:-${snmp_name:-N/A}}"
        echo "Vendor: ${vendor:-N/A}"
        echo "OS: ${snmp_descr:-N/A}"
        echo "Status: Up"
        echo "Interface: ${iface:-N/A}"
        echo "Source IP: ${src_ip:-N/A}"
        echo "Subnet: ${subnet:-N/A}"
        echo "Gateway: ${gateway:-Directly Connected}"
        echo "Management Protocol: ${management_protocols:-N/A}"
        echo "SSH Banner: ${ssh_banner:-N/A}"
        echo "HTTP Title: ${http_title:-N/A}"
        echo "Open Ports:"
        if [ -s "$ports_file" ]; then
            sed 's/^/  /' "$ports_file"
        else
            echo "  N/A"
        fi
        echo "Running Services:"
        if [ -s "$services_file" ]; then
            sed 's/^/  /' "$services_file"
        else
            echo "  N/A"
        fi
        echo "First Seen: $DATE_NOW"
        echo "Last Seen: $DATE_NOW"
        echo
    } >> "$OUTPUT_FILE"
}

write_lldp_info() {
    if require_cmd lldpcli; then
        {
            echo "Local LLDP Information:"
            echo
            lldpcli show neighbors details 2>/dev/null
            echo
        } >> "$OUTPUT_FILE"
    fi
}

main() {
    if [ "$#" -ne 1 ]; then
        print_usage
        exit 1
    fi

    if [ ! -f "$TARGET_FILE" ]; then
        echo "Target file not found: $TARGET_FILE" >&2
        exit 1
    fi

    if ! require_cmd nmap; then
        echo "nmap is required." >&2
        exit 1
    fi

    prepare_output_dir
    prompt_snmp_community
    write_header

    local live_targets
    live_targets="$TMP_DIR/live_targets.txt"

    echo "[*] Discovering live hosts from $TARGET_FILE ..."
    discover_live_hosts "$live_targets"

    echo "[*] Live hosts found:"
    cat "$live_targets"

    if [ ! -s "$live_targets" ]; then
        echo "No live hosts found." >> "$OUTPUT_FILE"
        finalize_output_permissions
        echo "Inventory written to: $OUTPUT_FILE"
        exit 0
    fi

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        echo "[*] Inventorying $ip ..."
        write_record "$ip"
    done < "$live_targets"

    write_lldp_info
    finalize_output_permissions

    echo "Inventory written to: $OUTPUT_FILE"
}

main "$@"
```

{% hint style="info" %}
Specify IP addresses
{% endhint %}

```bash
cat > targets.txt <<EOF
192.168.109.0/24
10.10.10.1
EOF
```

{% hint style="info" %}
Save & Execute
{% endhint %}

```bash
chmod +x network_node_inventory.sh
sudo ./network_node_inventory.sh targets.txt
```

### Cisco Products

#### CDP Neighbors

```
show cdp neighbors detail
```

#### Vlan Information

```
show vlan brief
show interfaces trunk
```

#### [Nessus](https://www.tenable.com/products/nessus)

1. Click New Scan
2. Select one of the templates in the Discovery section.
3. In the Settings section, enter a name for the scan in the Name field and specify the IP address or addresses in the Targets field.
4. In the Discover tab, you can select a scan type. By choosing Custom, you can customize the scan by selecting options such as TCP Scan, UDP Scan, Scan Fragile Devices, and other available settings.
5. Click Save.
6. Click the Start icon to begin the scan.
