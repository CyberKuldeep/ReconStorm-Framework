#!/bin/bash

set -euo pipefail

target=$1
base=$2
type=${3:-domain}

echo "[+] Recon Module Started..."

# -----------------------------
# CHECK TYPE
# -----------------------------
if [ "$type" != "domain" ]; then
    echo "[!] Recon skipped (Target is IP)"
    exit 0
fi

# -----------------------------
# CREATE DIR
# -----------------------------
mkdir -p "$base/recon"

# -----------------------------
# SUBDOMAIN ENUMERATION
# -----------------------------
echo "[+] Enumerating subdomains..."

subfinder -d "$target" -silent > "$base/recon/subfinder.txt" 2>/dev/null &
assetfinder --subs-only "$target" > "$base/recon/assetfinder.txt" 2>/dev/null &
amass enum -passive -d "$target" > "$base/recon/amass.txt" 2>/dev/null &

wait

# -----------------------------
# MERGE RESULTS
# -----------------------------
echo "[+] Merging subdomains..."

cat "$base/recon/"*.txt 2>/dev/null | sort -u | grep -E "$target$" > "$base/recon/subdomains.txt"

# -----------------------------
# LIVE HOST CHECK (FIXED)
# -----------------------------
echo "[+] Probing live hosts..."

if [ -s "$base/recon/subdomains.txt" ]; then
    httpx -l "$base/recon/subdomains.txt" \
        -threads 200 \
        -status-code \
        -title \
        -tech-detect \
        -web-server \
        -ip \
        -cdn \
        -follow-redirects \
        -silent \
        -o "$base/recon/live_hosts.txt"
else
    echo "[!] No subdomains found"
fi

# -----------------------------
# URL COLLECTION
# -----------------------------
echo "[+] Collecting URLs..."

gau "$target" > "$base/recon/urls.txt" 2>/dev/null || true

# -----------------------------
# CRAWLING
# -----------------------------
echo "[+] Crawling targets..."

if [ -s "$base/recon/live_hosts.txt" ]; then
    katana -list "$base/recon/live_hosts.txt" -silent > "$base/recon/crawled_urls.txt"
else
    echo "[!] No live hosts for crawling"
fi

# -----------------------------
# DONE
# -----------------------------
echo "[✔] Recon Module Completed"
