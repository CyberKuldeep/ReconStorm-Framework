#!/bin/bash

set -euo pipefail

target=$1
base=$2
type=${3:-domain}

echo "[+] Scanning Module Started..."

mkdir -p "$base/scan"

# -----------------------------
# RESOLVE DOMAIN → IP
# -----------------------------
if [ "$type" == "domain" ]; then
    echo "[+] Resolving domain to IP..."

    ip=$(dig +short "$target" | head -n1)

    if [ -z "$ip" ]; then
        echo "[!] Could not resolve domain"
        exit 1
    fi
else
    ip="$target"
fi

echo "[+] Target IP: $ip"

# -----------------------------
# FAST PORT SCAN (NAABU)
# -----------------------------
echo "[+] Running Naabu..."

naabu -host "$ip" -top-ports 1000 -silent -o "$base/scan/naabu.txt" || true

# -----------------------------
# MASSCAN (FAST FULL SCAN)
# -----------------------------
echo "[+] Running Masscan..."

masscan -p1-65535 "$ip" --rate 10000 -oG "$base/scan/masscan.txt" 2>/dev/null || true

# Extract open ports from masscan
grep "Ports:" "$base/scan/masscan.txt" | awk -F'Ports: ' '{print $2}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//' > "$base/scan/masscan_ports.txt" || true

# -----------------------------
# NMAP (SMART SCAN)
# -----------------------------
echo "[+] Running Nmap..."

if [ -s "$base/scan/masscan_ports.txt" ]; then
    ports=$(cat "$base/scan/masscan_ports.txt")
    echo "[+] Using ports from Masscan: $ports"

    nmap -sV -sC -T4 -p "$ports" "$ip" -oN "$base/scan/nmap.txt"
else
    echo "[!] No ports from Masscan, fallback to top ports"

    nmap -sV -sC -T4 --top-ports 1000 "$ip" -oN "$base/scan/nmap.txt"
fi

# -----------------------------
# DONE
# -----------------------------
echo "[✔] Scanning Module Completed"
