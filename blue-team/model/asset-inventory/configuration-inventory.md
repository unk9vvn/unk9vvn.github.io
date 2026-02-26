# Configuration Inventory

## Cheat Sheet

{% hint style="info" %}
Scan to find live IPs and Ports
{% endhint %}

```bash
#!/bin/bash

# Check if the network range is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <network_range>"
    echo "Example: $0 192.168.100.0/24"
    exit 1
fi

# Define your parameters
network="$1"  # Get the target network range from command line
temp_dir="/tmp"
naabu_output="$temp_dir/naabu.txt"
alive_ips_file="$temp_dir/alive_ips.txt"
banners_file="$temp_dir/banners.txt"
host_ports_map="$temp_dir/host-ports.map"
BH_THREAD=10  # Max concurrent nmap jobs

# Step 1: Scan for alive IPs
echo "Scanning for alive IPs in $network..."
nmap -sn "$network" | grep 'Nmap scan report for' | awk '{print $5}' > "$alive_ips_file"

# Step 2: Find open ports with Naabu
echo "Finding open ports with Naabu..."
naabu -list "$alive_ips_file" -p - -c 200 -rate 1000 -silent -o "$naabu_output"

# Step 3: Deduplicate host:port lines and construct host-ports mapping
echo "Deduplicating host:port lines..."
awk -F: '!seen[$0]++{           # de-duplicate host:port lines
           host=$1; port=$2
           ports[host]=ports[host] port ","
         }
         END{
           for(h in ports){
             sub(/,$/,"",ports[h])   # strip trailing comma
             printf "%s:%s\n", h, ports[h]
           }
         }' "$naabu_output" > "$host_ports_map"

# Step 4: Read hosts and ports
while IFS=: read -r host port_list; do
    [ -z "$host" ] || [ -z "$port_list" ] && continue

    {
        echo "Scanning $host for ports: $port_list..."
        nmap -n -sS -sV --mtu 5000 -T4 -Pn \
             -p "$port_list" "$host" >> "$banners_file" 2>&1
    } &

    # Store the process ID
    nmap_pids+=($!)

    # Limit concurrent nmap jobs
    while [ $(jobs -r | wc -l) -ge ${BH_THREAD} ]; do
        sleep 1
    done

done < "$host_ports_map"

# Wait for all Nmap jobs to finish
wait "${nmap_pids[@]}"

echo "Scanning complete. Processing results..."

filtered_output="$temp_dir/scan-results.txt"

awk '
/^Nmap scan report for/ {
    print ""
    print $0
    next
}
/^PORT[[:space:]]+STATE/ { print; next }
/^[0-9]+\/(tcp|udp)/ { print; next }
' "$banners_file" > "$filtered_output"

echo "Clean output saved to $filtered_output"
```

{% hint style="info" %}
Run Script
{% endhint %}

```bash
sudo nano subnet-scan.sh;sudo ./subnet-scan.sh $TARGET
```

### Windows Management Instrumentation (WMI)

{% hint style="info" %}
Extract full system configuration inventory for a single host
{% endhint %}

```ps1
$computer = "PC_NAME"

Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer
Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $computer
Get-WmiObject -Class Win32_Service -ComputerName $computer
Get-WmiObject -Class Win32_StartupCommand -ComputerName $computer
```

### Windows Management Infrastructure (MI)

{% hint style="info" %}
Extract full system configuration inventory for a single host
{% endhint %}

```ps1
$computer = "PC_NAME"

Get-CimInstance Win32_ComputerSystem -ComputerName $computer
Get-CimInstance Win32_OperatingSystem -ComputerName $computer
Get-CimInstance Win32_NetworkAdapterConfiguration -ComputerName $computer
Get-CimInstance Win32_Service -ComputerName $computer
Get-CimInstance Win32_StartupCommand -ComputerName $computer
```

{% hint style="info" %}
Extract full system configuration inventory for a single host using authentication
{% endhint %}

```ps1
$credential = Get-Credential

$computer = "PC_NAME"

$cimSession = New-CimSession -ComputerName $computer -Credential $credential

Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_ComputerSystem -CimSession $cimSession
Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_OperatingSystem -CimSession $cimSession
Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_NetworkAdapterConfiguration -CimSession $cimSession
Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_Service -CimSession $cimSession
Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_StartupCommand -CimSession $cimSession

Remove-CimSession -CimSession $cimSession
```

{% hint style="info" %}
Extract full system configuration inventory for a subnet
{% endhint %}

```ps1
$subnet = "192.168.1."  # Replace with your subnet
$startIP = 1            # Starting host IP suffix
$endIP = 254            # Ending host IP suffix

$credential = Get-Credential

for ($i = $startIP; $i -le $endIP; $i++) {
    $computer = $subnet + $i
    try {
        $cimSession = New-CimSession -ComputerName $computer -Credential $credential -ErrorAction Stop

        $computerSystem = Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_ComputerSystem -CimSession $cimSession
        $operatingSystem = Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_OperatingSystem -CimSession $cimSession
        $networkAdapterConfig = Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_NetworkAdapterConfiguration -CimSession $cimSession
        $services = Get-CimInstance -Namespace root\CIMv2 -ClassName Win32_Service -CimSession $cimSession

        Write-Output "Results for ${computer}:"
        $computerSystem
        $operatingSystem
        $networkAdapterConfig
        $services

        Remove-CimSession -CimSession $cimSession
    } catch {
        Write-Output "Failed to connect to ${computer}: $_"
    }
}
```
