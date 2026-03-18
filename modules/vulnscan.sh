#!/bin/bash

set -euo pipefail

target=$1
base=$2
type=${3:-domain}

echo "[+] Vulnerability Scan Module Started..."

mkdir -p "$base/vuln"

# -----------------------------
# NUCLEI SCAN
# -----------------------------
echo "[+] Running Nuclei..."

if [ -s "$base/recon/live_hosts.txt" ]; then
    nuclei -l "$base/recon/live_hosts.txt" \
        -severity critical,high,medium \
        -silent \
        -o "$base/vuln/nuclei.txt" || true
else
    echo "[!] No live hosts found for Nuclei"
fi

# -----------------------------
# NIKTO SCAN (SMART)
# -----------------------------
echo "[+] Running Nikto..."

if [ -s "$base/recon/live_hosts.txt" ]; then
    while read -r host; do
        nikto -h "$host" >> "$base/vuln/nikto.txt" 2>/dev/null || true
    done < "$base/recon/live_hosts.txt"
else
    echo "[!] No live hosts for Nikto"
fi

# -----------------------------
# XSS SCAN (DALFOX)
# -----------------------------
echo "[+] Running Dalfox (XSS)..."

if [ -s "$base/recon/urls.txt" ]; then

    # Filter only URLs with parameters (important)
    grep "=" "$base/recon/urls.txt" > "$base/tmp/param_urls.txt" || true

    if [ -s "$base/tmp/param_urls.txt" ]; then
        dalfox file "$base/tmp/param_urls.txt" \
            --mass \
            --silence \
            -o "$base/vuln/xss_scan.txt" || true
    else
        echo "[!] No parameterized URLs found for XSS"
    fi
else
    echo "[!] No URLs found"
fi

# -----------------------------
# DONE
# -----------------------------
echo "[✔] Vulnerability Scan Completed"
