#!/bin/bash

set -euo pipefail

target=$1
base=$2
type=${3:-domain}

echo "[+] Enumeration Module Started..."

mkdir -p "$base/enum" "$base/tmp"

# -----------------------------
# CHECK LIVE HOSTS
# -----------------------------
if [ ! -s "$base/recon/live_hosts.txt" ]; then
    echo "[!] No live hosts found, skipping enumeration"
    exit 0
fi

# -----------------------------
# HTTP ENUM (ADVANCED)
# -----------------------------
echo "[+] Running HTTPX Detailed Scan..."

httpx -l "$base/recon/live_hosts.txt" \
    -title -tech-detect -status-code -web-server -ip -cdn \
    -silent \
    -o "$base/enum/httpx_details.txt" || true

# -----------------------------
# DIRECTORY FUZZING (FFUF)
# -----------------------------
echo "[+] Running FFUF..."

while read -r host; do
    clean=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g')

    ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
        -u "$host/FUZZ" \
        -mc 200,204,301,302 \
        -t 50 \
        -silent \
        -o "$base/enum/ffuf_${clean}.json" \
        -of json || true

done < "$base/recon/live_hosts.txt"

# -----------------------------
# DIRSEARCH
# -----------------------------
echo "[+] Running Dirsearch..."

while read -r host; do
    clean=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g')

    dirsearch -u "$host" \
        -e php,html,js \
        --quiet \
        -o "$base/enum/dirsearch_${clean}.txt" || true

done < "$base/recon/live_hosts.txt"

# -----------------------------
# WAYBACK + PARAM ENUM
# -----------------------------
echo "[+] Extracting URLs & Parameters..."

if [ -s "$base/recon/urls.txt" ]; then
    sort -u "$base/recon/urls.txt" > "$base/enum/all_urls.txt"

    grep "=" "$base/enum/all_urls.txt" > "$base/enum/params.txt" || true
fi

# -----------------------------
# GF PATTERN MATCHING
# -----------------------------
echo "[+] Running GF Patterns..."

if [ -s "$base/enum/params.txt" ]; then
    gf xss "$base/enum/params.txt" > "$base/enum/gf_xss.txt" || true
    gf sqli "$base/enum/params.txt" > "$base/enum/gf_sqli.txt" || true
    gf ssrf "$base/enum/params.txt" > "$base/enum/gf_ssrf.txt" || true
fi

# -----------------------------
# JS FILE ANALYSIS
# -----------------------------
echo "[+] Extracting JS files..."

grep "\.js" "$base/enum/all_urls.txt" | sort -u > "$base/enum/js_files.txt" || true

# -----------------------------
# SUBDOMAIN TAKEOVER CHECK
# -----------------------------
echo "[+] Checking Subdomain Takeover..."

if [ -s "$base/recon/subdomains.txt" ]; then
    subzy run --targets "$base/recon/subdomains.txt" > "$base/enum/takeover.txt" || true
fi

# -----------------------------
# SCREENSHOT (OPTIONAL)
# -----------------------------
echo "[+] Capturing Screenshots..."

gowitness file -f "$base/recon/live_hosts.txt" -P "$base/enum/screenshots/" > /dev/null 2>&1 || true

# -----------------------------
# DONE
# -----------------------------
echo "[✔] Enumeration Module Completed"
