#!/bin/bash
# =============================================================
#  ReconStorm — Module: Enumeration
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

log_step "Enumeration Module: $TARGET"
mkdir -p "$BASE/enum" "$BASE/tmp" "$BASE/enum/screenshots"

# ── Determine host list ───────────────────────────────────────
if has_results "$BASE/recon/live_urls.txt"; then
    HOST_LIST="$BASE/recon/live_urls.txt"
elif has_results "$BASE/recon/live_hosts.txt"; then
    # Extract URLs from full httpx output (first field)
    awk '{print $1}' "$BASE/recon/live_hosts.txt" \
        | grep -E '^https?://' \
        | sort -u > "$BASE/tmp/live_urls_fallback.txt"
    HOST_LIST="$BASE/tmp/live_urls_fallback.txt"
elif has_results "$BASE/scan/web_services.txt"; then
    awk '{print $1}' "$BASE/scan/web_services.txt" \
        | grep -E '^https?://' \
        | sort -u > "$BASE/tmp/live_urls_fallback.txt"
    HOST_LIST="$BASE/tmp/live_urls_fallback.txt"
else
    log_warn "No live hosts found — skipping enumeration"
    exit 0
fi

HOST_COUNT=$(count_lines "$HOST_LIST")
log_info "Enumerating $HOST_COUNT hosts"

# ── Validate wordlists ────────────────────────────────────────
if [[ -z "$WORDLIST_COMMON" ]]; then
    log_warn "No common wordlist found — directory fuzzing will be skipped"
    log_warn "Install SecLists: https://github.com/danielmiessler/SecLists"
fi

# ── 1. Detailed httpx Fingerprinting ─────────────────────────
log_info "Detailed HTTP fingerprinting..."
require_tool httpx && httpx \
    -l "$HOST_LIST" \
    -title -tech-detect -status-code \
    -web-server -ip -cdn -cname \
    -content-length -content-type \
    -location \
    -random-agent \
    -silent \
    -threads "$HTTPX_THREADS" \
    ${PROXY:+-http-proxy "$PROXY"} \
    -o "$BASE/enum/httpx_full.txt" 2>/dev/null || true

log_ok "Fingerprinted $(count_lines "$BASE/enum/httpx_full.txt") hosts"

# ── 2. Directory Fuzzing (parallel, capped) ───────────────────
if [[ -n "$WORDLIST_COMMON" ]]; then
    log_info "Directory fuzzing (max $FFUF_THREADS threads per host)..."

    FFUF_PIDS=()
    MAX_PARALLEL=3   # max simultaneous ffuf instances

    while IFS= read -r host; do
        # Wait if too many parallel fuzzers running
        while [[ ${#FFUF_PIDS[@]} -ge $MAX_PARALLEL ]]; do
            for i in "${!FFUF_PIDS[@]}"; do
                if ! kill -0 "${FFUF_PIDS[$i]}" 2>/dev/null; then
                    unset 'FFUF_PIDS[i]'
                fi
            done
            FFUF_PIDS=("${FFUF_PIDS[@]}")
            sleep 1
        done

        clean=$(safe_filename "$host")

        if require_tool ffuf; then
            run_safe 180 ffuf \
                -w "$WORDLIST_COMMON" \
                -u "${host}/FUZZ" \
                -mc 200,201,204,301,302,307,401,403,405 \
                -fc 404 \
                -t "$FFUF_THREADS" \
                -ac \
                -r \
                -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
                ${PROXY:+-x "$PROXY"} \
                -o "$BASE/enum/ffuf_${clean}.json" \
                -of json \
                -s 2>/dev/null &
            FFUF_PIDS+=($!)
        fi
    done < "$HOST_LIST"

    # Wait for remaining
    for pid in "${FFUF_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Consolidate ffuf results
    for f in "$BASE/enum/ffuf_"*.json; do
        [[ -f "$f" ]] && python3 -c "
import json, sys
try:
    d = json.load(open('$f'))
    for r in d.get('results', []):
        print(r.get('status',''),r.get('url',''),r.get('length',''),r.get('words',''))
except: pass" >> "$BASE/enum/ffuf_results.txt" 2>/dev/null || true
    done

    log_ok "FFUF results: $(count_lines "$BASE/enum/ffuf_results.txt")"
fi

# ── 3. Dirsearch (complement, different wordlist) ─────────────
if require_tool dirsearch && [[ -n "$WORDLIST_DIR" ]]; then
    log_info "Running Dirsearch..."
    while IFS= read -r host; do
        clean=$(safe_filename "$host")
        run_safe 300 dirsearch \
            -u "$host" \
            -e php,html,js,json,txt,xml,bak,old,config,env \
            -w "$WORDLIST_DIR" \
            --random-agent \
            --quiet \
            --format plain \
            -o "$BASE/enum/dirsearch_${clean}.txt" 2>/dev/null || true
    done < "$HOST_LIST"
    log_ok "Dirsearch complete"
fi

# ── 4. URL & Parameter Extraction ────────────────────────────
log_info "Extracting URLs and parameters..."

# Merge all URL sources
merge_files "$BASE/enum/all_urls.txt" \
    "$BASE/recon/all_urls.txt"    \
    "$BASE/recon/in_scope_urls.txt" \
    "$BASE/recon/crawled.txt"     2>/dev/null || true

dedup_file "$BASE/enum/all_urls.txt"
URL_COUNT=$(count_lines "$BASE/enum/all_urls.txt")
log_ok "Total unique URLs: $URL_COUNT"

# Extract parameterized URLs
grep "=" "$BASE/enum/all_urls.txt" 2>/dev/null \
    | grep -vE '\.css=|\.js=' \
    | sort -u > "$BASE/enum/params.txt" || true

log_ok "Parameterized URLs: $(count_lines "$BASE/enum/params.txt")"

# ── 5. GF Pattern Matching ────────────────────────────────────
if require_tool gf && has_results "$BASE/enum/params.txt"; then
    log_info "GF pattern matching..."

    GF_PATTERNS=(xss sqli ssrf lfi rce idor redirect)
    for pattern in "${GF_PATTERNS[@]}"; do
        gf "$pattern" "$BASE/enum/params.txt" \
            > "$BASE/enum/gf_${pattern}.txt" 2>/dev/null || true
        count=$(count_lines "$BASE/enum/gf_${pattern}.txt")
        [[ $count -gt 0 ]] && log_ok "  gf_$pattern: $count URLs"
    done
fi

# ── 6. JS File Analysis ───────────────────────────────────────
log_info "Extracting and analyzing JavaScript files..."

# Collect JS URLs
grep -iE '\.js(\?|$)' "$BASE/enum/all_urls.txt" 2>/dev/null \
    | sort -u > "$BASE/enum/js_files.txt" || true

JS_COUNT=$(count_lines "$BASE/enum/js_files.txt")
log_info "Found $JS_COUNT JavaScript files"

if [[ $JS_COUNT -gt 0 ]] && require_tool curl; then
    mkdir -p "$BASE/enum/js_downloaded"
    while IFS= read -r js_url; do
        clean=$(safe_filename "$js_url")
        run_safe 15 curl -sk \
            -H "User-Agent: Mozilla/5.0" \
            ${PROXY:+-x "$PROXY"} \
            "$js_url" -o "$BASE/enum/js_downloaded/${clean}.js" 2>/dev/null || true
    done < <(head -n 50 "$BASE/enum/js_files.txt")  # cap at 50

    # Extract secrets/endpoints from JS
    log_info "Scanning JS files for secrets/endpoints..."
    {
        # API keys, tokens, secrets
        grep -rhoE \
            '(api[_-]?key|apikey|secret|token|password|passwd|auth)["\s:=]+["'"'"'][A-Za-z0-9+/=_-]{8,}' \
            "$BASE/enum/js_downloaded/" 2>/dev/null

        # Endpoints in JS
        grep -rhoE '(["'"'"'])(/[a-zA-Z0-9_./-]+)(["'"'"'])' \
            "$BASE/enum/js_downloaded/" 2>/dev/null \
            | sed "s/[\"']//g" | sort -u
    } > "$BASE/enum/js_secrets.txt" 2>/dev/null || true

    JS_SECRET_COUNT=$(count_lines "$BASE/enum/js_secrets.txt")
    [[ $JS_SECRET_COUNT -gt 0 ]] && log_warn "Potential secrets found in JS: $JS_SECRET_COUNT hits"

    # Use secretfinder/linkfinder if available
    if require_tool python3; then
        LINKFINDER=$(find /opt /usr /home -name "linkfinder.py" 2>/dev/null | head -n1)
        if [[ -n "$LINKFINDER" ]]; then
            log_info "Running LinkFinder..."
            while IFS= read -r js_url; do
                python3 "$LINKFINDER" -i "$js_url" -o cli 2>/dev/null \
                    >> "$BASE/enum/linkfinder.txt" || true
            done < <(head -n 30 "$BASE/enum/js_files.txt")
        fi
    fi
fi

# ── 7. Subdomain Takeover Detection ──────────────────────────
if require_tool subzy && has_results "$BASE/recon/subdomains.txt"; then
    log_info "Checking subdomain takeover..."
    run_safe 120 subzy run \
        --targets "$BASE/recon/subdomains.txt" \
        --hide-fails \
        --output "$BASE/enum/takeover.txt" 2>/dev/null || true

    TAKEOVER_COUNT=$(count_lines "$BASE/enum/takeover.txt")
    [[ $TAKEOVER_COUNT -gt 0 ]] && log_warn "Potential takeovers: $TAKEOVER_COUNT"
fi

# ── 8. Screenshots ────────────────────────────────────────────
if require_tool gowitness && has_results "$HOST_LIST"; then
    log_info "Capturing screenshots..."
    # Check for chromium/chrome
    if command -v chromium-browser &>/dev/null || \
       command -v chromium &>/dev/null || \
       command -v google-chrome &>/dev/null; then
        run_safe 120 gowitness file \
            -f "$HOST_LIST" \
            -P "$BASE/enum/screenshots/" \
            --no-prompt 2>/dev/null || true
        SCREENSHOT_COUNT=$(find "$BASE/enum/screenshots" -name "*.png" 2>/dev/null | wc -l)
        log_ok "Screenshots: $SCREENSHOT_COUNT"
    else
        log_warn "Chrome/Chromium not found — screenshots skipped"
    fi
fi

# ── 9. CORS Misconfiguration Check ───────────────────────────
log_info "Checking CORS misconfigurations..."
while IFS= read -r host; do
    result=$(curl -sk -I \
        -H "Origin: https://evil.com" \
        -H "User-Agent: Mozilla/5.0" \
        "$host" 2>/dev/null | grep -i "Access-Control")
    if echo "$result" | grep -qi "evil.com"; then
        echo "CORS MISCONFIGURED: $host" >> "$BASE/enum/cors_issues.txt"
    fi
done < <(head -n 20 "$HOST_LIST")  # cap for speed

CORS_COUNT=$(count_lines "$BASE/enum/cors_issues.txt")
[[ $CORS_COUNT -gt 0 ]] && log_warn "CORS misconfigurations: $CORS_COUNT"

# ── Summary ───────────────────────────────────────────────────
echo ""
log_ok "Enumeration Summary:"
log_ok "  Total URLs     : $(count_lines "$BASE/enum/all_urls.txt")"
log_ok "  Param URLs     : $(count_lines "$BASE/enum/params.txt")"
log_ok "  JS Files       : $JS_COUNT"
log_ok "  JS Secrets     : $(count_lines "$BASE/enum/js_secrets.txt")"
log_ok "  CORS Issues    : $CORS_COUNT"
log_ok "  Takeover Flags : $(count_lines "$BASE/enum/takeover.txt" 2>/dev/null || echo 0)"
