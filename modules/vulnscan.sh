#!/bin/bash
# =============================================================
#  ReconStorm — Module: Vulnerability Scan
#  Args: $1=target  $2=base_dir  $3=type
# =============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/config/config.sh"
source "$SCRIPT_DIR/lib/logger.sh"
source "$SCRIPT_DIR/lib/utils.sh"

TARGET="$1"
BASE="$2"
TYPE="${3:-domain}"

log_step "Vulnerability Scan Module: $TARGET"
mkdir -p "$BASE/vuln" "$BASE/tmp"

# ── Resolve host list ─────────────────────────────────────────
if has_results "$BASE/recon/live_urls.txt"; then
    HOST_LIST="$BASE/recon/live_urls.txt"
elif has_results "$BASE/recon/live_hosts.txt"; then
    awk '{print $1}' "$BASE/recon/live_hosts.txt" \
        | grep -E '^https?://' | sort -u \
        > "$BASE/tmp/vuln_hosts.txt"
    HOST_LIST="$BASE/tmp/vuln_hosts.txt"
elif has_results "$BASE/scan/web_services.txt"; then
    awk '{print $1}' "$BASE/scan/web_services.txt" \
        | grep -E '^https?://' | sort -u \
        > "$BASE/tmp/vuln_hosts.txt"
    HOST_LIST="$BASE/tmp/vuln_hosts.txt"
else
    log_warn "No live hosts — building target from scan data"
    if has_results "$BASE/scan/target_ip.txt"; then
        IP=$(cat "$BASE/scan/target_ip.txt")
        echo "http://$IP" > "$BASE/tmp/vuln_hosts.txt"
        [[ "$TYPE" == "domain" ]] && echo "https://$TARGET" >> "$BASE/tmp/vuln_hosts.txt"
        HOST_LIST="$BASE/tmp/vuln_hosts.txt"
    else
        log_error "No scan data available — skipping vuln scan"
        exit 0
    fi
fi

HOST_COUNT=$(count_lines "$HOST_LIST")
log_info "Scanning $HOST_COUNT host(s)"

# ── 1. Nuclei — Full Template Scan ───────────────────────────
if require_tool nuclei; then
    # Update templates if older than 24 hours
    NUCLEI_TS_FILE="$HOME/.nuclei-templates-updated"
    if [[ ! -f "$NUCLEI_TS_FILE" ]] || \
       [[ $(( $(date +%s) - $(stat -c %Y "$NUCLEI_TS_FILE" 2>/dev/null || echo 0) )) -gt 86400 ]]; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates &>/dev/null && touch "$NUCLEI_TS_FILE" || true
    else
        log_info "Nuclei templates up to date"
    fi

    log_info "Running Nuclei (severity: critical, high, medium)..."
    run_safe 600 nuclei \
        -l "$HOST_LIST" \
        -severity critical,high,medium \
        -rate-limit "$NUCLEI_RATE" \
        -bulk-size 25 \
        -concurrency 10 \
        -silent \
        -no-color \
        ${PROXY:+-proxy "$(proxy_flag_nuclei)"} \
        -o "$BASE/vuln/nuclei_all.txt" 2>/dev/null || true

    # Also run specific high-value tag groups separately for better coverage
    for tag in cve exposure misconfig default-login sqli xss lfi rce; do
        if has_results "$BASE/recon/live_urls.txt" || has_results "$HOST_LIST"; then
            run_safe 300 nuclei \
                -l "$HOST_LIST" \
                -tags "$tag" \
                -rate-limit 50 \
                -silent \
                -no-color \
                -o "$BASE/vuln/nuclei_${tag}.txt" 2>/dev/null || true
        fi
    done

    # Merge nuclei results
    merge_files "$BASE/vuln/nuclei.txt" \
        "$BASE/vuln/nuclei_all.txt" \
        "$BASE/vuln/nuclei_cve.txt" \
        "$BASE/vuln/nuclei_exposure.txt" \
        "$BASE/vuln/nuclei_misconfig.txt" \
        "$BASE/vuln/nuclei_default-login.txt" \
        "$BASE/vuln/nuclei_sqli.txt" \
        "$BASE/vuln/nuclei_xss.txt" \
        "$BASE/vuln/nuclei_lfi.txt" \
        "$BASE/vuln/nuclei_rce.txt" 2>/dev/null || true

    # Severity counts
    CRITICAL=$(grep -c "\[critical\]" "$BASE/vuln/nuclei.txt" 2>/dev/null || echo 0)
    HIGH=$(grep -c "\[high\]" "$BASE/vuln/nuclei.txt" 2>/dev/null || echo 0)
    MEDIUM=$(grep -c "\[medium\]" "$BASE/vuln/nuclei.txt" 2>/dev/null || echo 0)
    log_ok "Nuclei findings — Critical: $CRITICAL | High: $HIGH | Medium: $MEDIUM"
fi

# ── 2. XSS — Dalfox ──────────────────────────────────────────
XSS_INPUT=""
if has_results "$BASE/enum/gf_xss.txt"; then
    XSS_INPUT="$BASE/enum/gf_xss.txt"
elif has_results "$BASE/enum/params.txt"; then
    # Fallback: all parameterized URLs
    XSS_INPUT="$BASE/enum/params.txt"
fi

if [[ -n "$XSS_INPUT" ]] && require_tool dalfox; then
    log_info "Running Dalfox XSS scan..."

    # Deduplicate and cap to 200 URLs (dalfox can be very slow)
    sort -u "$XSS_INPUT" | head -n 200 > "$BASE/tmp/xss_input.txt"

    run_safe "$DALFOX_TIMEOUT" dalfox file "$BASE/tmp/xss_input.txt" \
        --mass \
        --silence \
        --no-color \
        --timeout 10 \
        --worker 20 \
        --waf-bypass \
        ${PROXY:+--proxy "$PROXY"} \
        -o "$BASE/vuln/xss_dalfox.txt" 2>/dev/null || true

    XSS_COUNT=$(count_lines "$BASE/vuln/xss_dalfox.txt")
    log_ok "XSS findings: $XSS_COUNT"
fi

# ── 3. Nikto (limited concurrency, timeout per host) ─────────
if require_tool nikto && has_results "$HOST_LIST"; then
    log_info "Running Nikto (max $NIKTO_TIMEOUT s/host)..."

    # Run nikto in background batches (max 3 parallel)
    NIKTO_PIDS=()
    MAX_NIKTO=3

    while IFS= read -r host; do
        while [[ ${#NIKTO_PIDS[@]} -ge $MAX_NIKTO ]]; do
            for i in "${!NIKTO_PIDS[@]}"; do
                if ! kill -0 "${NIKTO_PIDS[$i]}" 2>/dev/null; then
                    unset 'NIKTO_PIDS[i]'
                fi
            done
            NIKTO_PIDS=("${NIKTO_PIDS[@]}")
            sleep 2
        done

        clean=$(safe_filename "$host")
        (
            run_safe "$NIKTO_TIMEOUT" nikto \
                -h "$host" \
                -nointeractive \
                -Tuning 1234578 \
                ${PROXY:+-useproxy "$PROXY"} \
                -output "$BASE/vuln/nikto_${clean}.txt" 2>/dev/null || true
        ) &
        NIKTO_PIDS+=($!)
    done < <(head -n 10 "$HOST_LIST")  # cap at 10 for speed

    for pid in "${NIKTO_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Merge nikto results
    cat "$BASE/vuln/nikto_"*.txt 2>/dev/null \
        | sort -u > "$BASE/vuln/nikto.txt" || true

    log_ok "Nikto complete — $(count_lines "$BASE/vuln/nikto.txt") findings"
fi

# ── 4. SQL Injection Detection (gf → sqlmap preview) ─────────
if has_results "$BASE/enum/gf_sqli.txt"; then
    log_info "Checking SQLi candidates (passive verification)..."

    # Quick heuristic: test with error-based payloads via curl
    while IFS= read -r url; do
        # Append simple SQLi payload to each param
        test_url=$(echo "$url" | sed "s/=\([^&]*\)/=\1'/g")
        response=$(curl -sk --max-time 10 \
            -H "User-Agent: Mozilla/5.0" \
            ${PROXY:+-x "$PROXY"} \
            "$test_url" 2>/dev/null | head -c 2000)

        if echo "$response" | grep -qiE \
            "sql syntax|mysql_fetch|ora-[0-9]+|syntax error.*sql|unclosed quotation|pg_query|sqlite_error"; then
            echo "POTENTIAL_SQLI: $url" >> "$BASE/vuln/sqli_candidates.txt"
        fi
    done < <(head -n 50 "$BASE/enum/gf_sqli.txt")

    SQLI_COUNT=$(count_lines "$BASE/vuln/sqli_candidates.txt")
    [[ $SQLI_COUNT -gt 0 ]] && log_warn "Potential SQLi: $SQLI_COUNT endpoints"
fi

# ── 5. LFI Check ─────────────────────────────────────────────
if has_results "$BASE/enum/gf_lfi.txt"; then
    log_info "Checking LFI candidates..."
    LFI_PAYLOADS=(
        "../../../../etc/passwd"
        "../../../../etc/shadow"
        "../../../../windows/win.ini"
        "....//....//....//etc/passwd"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    )

    while IFS= read -r url; do
        for payload in "${LFI_PAYLOADS[@]}"; do
            test_url=$(echo "$url" | sed "s/=\([^&]*\)/=$payload/g")
            response=$(curl -sk --max-time 8 \
                -H "User-Agent: Mozilla/5.0" \
                ${PROXY:+-x "$PROXY"} \
                "$test_url" 2>/dev/null | head -c 1000)

            if echo "$response" | grep -qE "root:x:|bin:x:|daemon:x:|\\[extensions\\]"; then
                echo "LFI_CONFIRMED: $test_url" >> "$BASE/vuln/lfi_confirmed.txt"
                break
            fi
        done
    done < <(head -n 30 "$BASE/enum/gf_lfi.txt")

    LFI_COUNT=$(count_lines "$BASE/vuln/lfi_confirmed.txt")
    [[ $LFI_COUNT -gt 0 ]] && log_warn "Confirmed LFI: $LFI_COUNT"
fi

# ── 6. Open Redirect Check ────────────────────────────────────
if has_results "$BASE/enum/gf_redirect.txt"; then
    log_info "Checking open redirect candidates..."
    REDIRECT_PAYLOADS=("https://evil.com" "//evil.com" "/\\evil.com")

    while IFS= read -r url; do
        for payload in "${REDIRECT_PAYLOADS[@]}"; do
            test_url=$(echo "$url" | sed "s/=\([^&]*\)/=$payload/g")
            location=$(curl -sk --max-time 8 -I \
                -H "User-Agent: Mozilla/5.0" \
                ${PROXY:+-x "$PROXY"} \
                "$test_url" 2>/dev/null \
                | grep -i "^location:" | tr -d '\r')
            if echo "$location" | grep -qi "evil.com"; then
                echo "OPEN_REDIRECT: $test_url → $location" >> "$BASE/vuln/open_redirect.txt"
            fi
        done
    done < <(head -n 30 "$BASE/enum/gf_redirect.txt")

    REDIR_COUNT=$(count_lines "$BASE/vuln/open_redirect.txt")
    [[ $REDIR_COUNT -gt 0 ]] && log_warn "Open redirects: $REDIR_COUNT"
fi

# ── 7. Shodan CVE Lookup (if API available) ───────────────────
if [[ -n "${SHODAN_API:-}" ]] && has_results "$BASE/scan/target_ip.txt"; then
    IP=$(cat "$BASE/scan/target_ip.txt")
    log_info "Shodan CVE lookup for $IP..."
    curl -s --max-time 15 \
        "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API" \
        2>/dev/null \
        | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    vulns = d.get('vulns', {})
    for cve, info in vulns.items():
        print(f'{cve}: CVSS={info.get(\"cvss\",\"N/A\")} {info.get(\"summary\",\"\")[:100]}')
except: pass
" > "$BASE/vuln/shodan_cves.txt" 2>/dev/null || true

    SHODAN_CVE_COUNT=$(count_lines "$BASE/vuln/shodan_cves.txt")
    [[ $SHODAN_CVE_COUNT -gt 0 ]] && log_warn "Shodan CVEs: $SHODAN_CVE_COUNT"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
log_ok "Vulnerability Scan Summary:"
log_ok "  Nuclei Total   : $(count_lines "$BASE/vuln/nuclei.txt")"
[[ -f "$BASE/vuln/nuclei.txt" ]] && {
    log_ok "    Critical     : $CRITICAL"
    log_ok "    High         : $HIGH"
    log_ok "    Medium       : $MEDIUM"
}
log_ok "  XSS (Dalfox)   : $(count_lines "$BASE/vuln/xss_dalfox.txt" 2>/dev/null || echo 0)"
log_ok "  SQLi Candidates: $(count_lines "$BASE/vuln/sqli_candidates.txt" 2>/dev/null || echo 0)"
log_ok "  LFI Confirmed  : $(count_lines "$BASE/vuln/lfi_confirmed.txt" 2>/dev/null || echo 0)"
log_ok "  Open Redirects : $(count_lines "$BASE/vuln/open_redirect.txt" 2>/dev/null || echo 0)"
log_ok "  Shodan CVEs    : $(count_lines "$BASE/vuln/shodan_cves.txt" 2>/dev/null || echo 0)"
