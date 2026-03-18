#!/bin/bash

set -uo pipefail   # removed -e (IMPORTANT FIX)

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
# OUTPUT SETUP
# -----------------------------
date=$(date +%F)
base_dir="output/${target}-${date}"

mkdir -p "$base_dir"/{recon,scan,enum,vuln,exploit,logs,tmp}
logfile="$base_dir/logs/run.log"

# -----------------------------
# LIVE LOGGING (IMPORTANT 🔥)
# -----------------------------
exec > >(tee -a "$logfile") 2>&1

echo "====================================="
echo "[🔥] ReconStorm Framework Started"
echo "====================================="
echo "[+] Target : $target"
echo "[+] Type   : $TYPE"
echo "[+] Output : $base_dir"
echo "====================================="

# -----------------------------
# ENVIRONMENT FIX (PATH)
# -----------------------------
echo "[+] Fixing PATH..."

export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin

# -----------------------------
# TOOL CHECK (IMPROVED)
# -----------------------------
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo "[✔] Found: $1"
    else
        echo "[✘] Missing: $1"
        MISSING=1
    fi
}

echo "[+] Checking essential tools..."
for tool in subfinder httpx nuclei nmap gau katana; do
    check_tool $tool
done

if [ "${MISSING:-0}" -eq 1 ]; then
    echo "[!] Some tools are missing. Script will continue but results may be incomplete."
fi

# -----------------------------
# MODULE RUNNER (FIXED 🔥)
# -----------------------------
run_module() {
    name=$1
    script=$2

    if [ -f "$script" ]; then
        echo ""
        echo "[+] Running $name..."

        # Run safely (no crash)
        if bash "$script" "$target" "$base_dir" "$TYPE"; then
            echo "[✔] $name completed"
        else
            echo "[!] $name failed but continuing..."
        fi

    else
        echo "[✘] Module missing: $script"
    fi
}

# -----------------------------
# EXECUTION FLOW
# -----------------------------

if [ "$TYPE" == "domain" ]; then
    run_module "Recon" "modules/recon.sh"
else
    echo "[!] Skipping Recon (IP target)"
fi

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
