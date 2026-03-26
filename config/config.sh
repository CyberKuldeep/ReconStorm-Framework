#!/bin/bash
# =============================================================
#  ReconStorm — Global Configuration
#  Source this file in all modules via: source config/config.sh
# =============================================================

# ── API Keys (load from api_keys.conf if present) ─────────────
API_KEYS_FILE="$(dirname "${BASH_SOURCE[0]}")/api_keys.conf"
if [[ -f "$API_KEYS_FILE" ]]; then
    # Safe source: only export KEY="value" lines
    while IFS='=' read -r key val; do
        [[ "$key" =~ ^[A-Z_]+$ ]] && [[ -n "$val" ]] && export "$key"="$val"
    done < <(grep -E '^[A-Z_]+=".+"' "$API_KEYS_FILE" | tr -d '"')
fi

# ── Output ────────────────────────────────────────────────────
OUTPUT_DIR="${OUTPUT_DIR:-output}"

# ── Concurrency / Rate limits ─────────────────────────────────
HTTPX_THREADS="${HTTPX_THREADS:-150}"
FFUF_THREADS="${FFUF_THREADS:-50}"
NUCLEI_RATE="${NUCLEI_RATE:-150}"
MASSCAN_RATE="${MASSCAN_RATE:-5000}"  # lowered default (10000 can get banned)
KATANA_DEPTH="${KATANA_DEPTH:-3}"

# ── Timeouts (seconds) ────────────────────────────────────────
GAU_TIMEOUT="${GAU_TIMEOUT:-60}"
NIKTO_TIMEOUT="${NIKTO_TIMEOUT:-300}"   # 5 min per host
DALFOX_TIMEOUT="${DALFOX_TIMEOUT:-120}"

# ── Wordlists ─────────────────────────────────────────────────
# Auto-detect common wordlist paths
_wl_candidates=(
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
    "$HOME/SecLists/Discovery/Web-Content/common.txt"
    "/opt/SecLists/Discovery/Web-Content/common.txt"
)
WORDLIST_COMMON=""
for _wl in "${_wl_candidates[@]}"; do
    if [[ -f "$_wl" ]]; then
        WORDLIST_COMMON="$_wl"
        break
    fi
done

_wl_dir_candidates=(
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "$HOME/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
)
WORDLIST_DIR=""
for _wl in "${_wl_dir_candidates[@]}"; do
    if [[ -f "$_wl" ]]; then
        WORDLIST_DIR="$_wl"
        break
    fi
done

# ── Nuclei templates ──────────────────────────────────────────
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"

# ── Proxy (optional — set for BurpSuite integration) ──────────
# PROXY="http://127.0.0.1:8080"
PROXY="${PROXY:-}"

# ── Attacker IP (used by exploitation module) ─────────────────
ATTACKER_IP="${ATTACKER_IP:-}"
LPORT="${LPORT:-4444}"

# ── Export all ────────────────────────────────────────────────
export OUTPUT_DIR HTTPX_THREADS FFUF_THREADS NUCLEI_RATE MASSCAN_RATE
export KATANA_DEPTH GAU_TIMEOUT NIKTO_TIMEOUT DALFOX_TIMEOUT
export WORDLIST_COMMON WORDLIST_DIR NUCLEI_TEMPLATES
export PROXY ATTACKER_IP LPORT
export GITHUB_TOKEN SHODAN_API CENSYS_ID CENSYS_SECRET
