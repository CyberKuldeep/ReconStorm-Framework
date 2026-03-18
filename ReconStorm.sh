#!/bin/bash

set -euo pipefail

target=${1:-}

# -----------------------------
# INPUT VALIDATION
# -----------------------------
if [ -z "$target" ]; then
    echo "Usage: ./ReconStorm.sh <domain | IP>"
    exit 1
fi

# -----------------------------
# TARGET TYPE DETECTION
# -----------------------------
if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    TYPE="ip"
else
    TYPE="domain"
fi

# -----------------------------
# LOAD CONFIG (SAFE)
# -----------------------------
if [ -f config/api_keys.conf ]; then
    source config/api_keys.conf
else
    echo "[!] No API config found (Skipping APIs)"
fi

# -----------------------------
# OUTPUT SETUP
# -----------------------------
date=$(date +%F)
base_dir="output/${target}-${date}"

mkdir -p "$base_dir"/{recon,scan,enum,vuln,exploit,logs,tmp}

logfile="$base_dir/logs/run.log"

echo "====================================="
echo "[🔥] ReconStorm Framework Started"
echo "====================================="
echo "[+] Target : $target"
echo "[+] Type   : $TYPE"
echo "[+] Output : $base_dir"
echo "====================================="

# -----------------------------
# TOOL CHECK (IMPORTANT)
# -----------------------------
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "[✘] Missing tool: $1"
    fi
}

echo "[+] Checking essential tools..."
for tool in subfinder httpx nuclei nmap gau katana; do
    check_tool $tool
done

# -----------------------------
# MODULE RUNNER
# -----------------------------
run_module() {
    name=$1
    script=$2

    if [ -f "$script" ]; then
        echo "[+] Running $name..."
        echo "[+] Running $name..." >> "$logfile"

        bash "$script" "$target" "$base_dir" "$TYPE" >> "$logfile" 2>&1

        echo "[✔] $name completed"
    else
        echo "[✘] Module missing: $script"
    fi
}

# -----------------------------
# EXECUTION FLOW
# -----------------------------

# Recon → Only domain
if [ "$TYPE" == "domain" ]; then
    run_module "Recon" "modules/recon.sh"
else
    echo "[!] Skipping Recon (IP target)"
fi

# Core modules (both)
run_module "Scanning" "modules/scanning.sh"
run_module "Enumeration" "modules/enumeration.sh"
run_module "Vulnerability Scan" "modules/vulnscan.sh"
run_module "Exploitation" "modules/exploitation.sh"

# -----------------------------
# FINAL SUMMARY
# -----------------------------
echo ""
echo "====================================="
echo "[🔥] ReconStorm Completed!"
echo "====================================="
echo "[📁] Output : $base_dir"
echo "[📜] Logs   : $logfile"
echo "====================================="
