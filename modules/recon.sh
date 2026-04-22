#!/bin/bash
# =============================================================
#  ReconStorm — Module: Recon
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

log_step "Recon Module: $TARGET"

if [[ "$TYPE" != "domain" ]]; then
    log_info "Skipping recon (IP target — use scanning module)"
    exit 0
fi

mkdir -p "$BASE/recon" "$BASE/tmp"

# ── 1. Passive Subdomain Enumeration (parallel) ───────────────
log_info "Passive subdomain enumeration..."

pids=()

if require_tool subfinder; then
    subfinder -d "$TARGET" -silent \
        ${GITHUB_TOKEN:+-authorization "token $GITHUB_TOKEN"} \
        -o "$BASE/recon/subfinder.txt" 2>/dev/null &
    pids+=($!)
fi

if require_tool assetfinder; then
    assetfinder --subs-only "$TARGET" \
        > "$BASE/recon/assetfinder.txt" 2>/dev/null &
    pids+=($!)
fi

if require_tool amass; then
    # passive only — amass active is very slow and noisy
    timeout 120 amass enum -passive -d "$TARGET" \
        -o "$BASE/recon/amass.txt" 2>/dev/null &
    pids+=($!)
fi

# GitHub dorking via API (if token set)
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    log_info "GitHub subdomain dorking..."
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/search/code?q=%22.$TARGET%22&per_page=100" \
        | grep -oP '[\w.-]+\.$TARGET' 2>/dev/null \
        | sort -u > "$BASE/recon/github_subs.txt" || true
fi

# Shodan (if API key set)
if require_tool shodan && [[ -n "${SHODAN_API:-}" ]]; then
    log_info "Shodan subdomain lookup..."
    shodan host "$TARGET" 2>/dev/null | grep -oP '[\w.-]+\.$TARGET' \
        > "$BASE/recon/shodan_subs.txt" || true
fi

# Certificiate transparency (crt.sh — no API key needed)
log_info "Certificate transparency (crt.sh)..."
curl -s --max-time 30 \
    "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | grep -oP '"name_value":"[^"]*"' \
    | sed 's/"name_value":"//;s/"//' \
    | sed 's/\*\.//g' \
    | grep -E "\.${TARGET}$" \
    | sort -u > "$BASE/recon/crtsh.txt" || true

wait_jobs "${pids[@]}"

# ── 2. Merge & Filter Subdomains ─────────────────────────────
log_info "Merging subdomain results..."
merge_files "$BASE/recon/subdomains_raw.txt" \
    "$BASE/recon/subfinder.txt"  \
    "$BASE/recon/assetfinder.txt" \
    "$BASE/recon/amass.txt"      \
    "$BASE/recon/github_subs.txt" \
    "$BASE/recon/shodan_subs.txt" \
    "$BASE/recon/crtsh.txt"      \
    2>/dev/null || true

# Validate: must end with target domain, no wildcards, no blank
grep -E "^[a-zA-Z0-9][a-zA-Z0-9._-]*\.${TARGET}$" \
    "$BASE/recon/subdomains_raw.txt" 2>/dev/null \
    | sort -u > "$BASE/recon/subdomains.txt" || true

SUBDOMAIN_COUNT=$(count_lines "$BASE/recon/subdomains.txt")
log_ok "Found $SUBDOMAIN_COUNT unique subdomains"

# ── 3. DNS Resolution & Wildcard Detection ────────────────────
log_info "Detecting wildcard DNS..."
RAND_SUB="$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12).${TARGET}"
if dig +short "$RAND_SUB" 2>/dev/null | grep -qE '^[0-9]'; then
    log_warn "Wildcard DNS detected! Results may include false positives."
    echo "WILDCARD_DETECTED=1" >> "$BASE/recon/dns_info.txt"
fi

# ── 4. Live Host Probing ──────────────────────────────────────
if ! has_results "$BASE/recon/subdomains.txt"; then
    log_warn "No subdomains found — skipping live host probe"
else
    log_info "Probing live hosts with httpx ($HTTPX_THREADS threads)..."

    # 1. Use -no-color to ensure awk doesn't grab ANSI escape sequences
    # 2. Use -csv or -json if you want to be even safer
    require_tool httpx && httpx \
        -l "$BASE/recon/subdomains.txt" \
        -threads "$HTTPX_THREADS" \
        -status-code -title -tech-detect -web-server -ip -cdn -cname \
        -follow-redirects -random-agent -silent -no-color \
        -retries 2 \
        ${PROXY:+-http-proxy "$PROXY"} \
        -o "$BASE/recon/live_hosts.txt"

    if [ -s "$BASE/recon/live_hosts.txt" ]; then
        # Use awk to grab the URL, but ensure we handle potential [status] prefixes
        awk '{for(i=1;i<=NF;i++) if($i ~ /^https?:\/\//) {print $i; break}}' "$BASE/recon/live_hosts.txt" \
            | sort -u > "$BASE/recon/live_urls.txt"
        
        LIVE_COUNT=$(count_lines "$BASE/recon/live_urls.txt")
        log_ok "Found $LIVE_COUNT live hosts"
    else
        log_warn "httpx completed but found 0 live hosts"
    fi
fi

# ── 5. URL Collection ─────────────────────────────────────────
log_info "Collecting historical URLs..."
pids=()

# Use gau as primary
if require_tool gau; then
    run_safe "$GAU_TIMEOUT" gau "$TARGET" \
        --threads 5 \
        --blacklist png,jpg,gif,ico,css,woff,woff2,ttf \
        > "$BASE/recon/gau.txt" 2>/dev/null &
    pids+=($!)
fi

# Use waybackurls only if gau isn't present, or as a small supplement
if require_tool waybackurls; then
    echo "$TARGET" | run_safe 60 waybackurls \
        > "$BASE/recon/wayback.txt" 2>/dev/null &
    pids+=($!)
fi

# ONLY wait if there are actual PIDs to wait for
if [ ${#pids[@]} -gt 0 ]; then
    wait "${pids[@]}"
fi

# Use 'cat -s' to suppress errors if one file was never created
cat "$BASE/recon/gau.txt" "$BASE/recon/wayback.txt" 2>/dev/null > "$BASE/recon/urls_raw.txt" || true

# Filter garbage extensions
# ADDED: js, webp, and fonts to the regex for better recon hygiene
grep -vE "\.(png|jpg|jpeg|gif|ico|css|woff|woff2|ttf|eot|svg|mp4|mp3|pdf|webp|js)(\?|$)" \
    "$BASE/recon/urls_raw.txt" 2>/dev/null \
    | sort -u > "$BASE/recon/urls.txt" || true

URL_COUNT=$(count_lines "$BASE/recon/urls.txt")
log_ok "Collected $URL_COUNT filtered URLs"

# ── 6. Crawling ───────────────────────────────────────────────
if has_results "$BASE/recon/live_urls.txt"; then
    log_info "Crawling live hosts with katana (depth=$KATANA_DEPTH)..."
    
    # 1. Added -no-color for cleaner logs
    # 2. Added -automatic-proxy if PROXY is not set (optional)
    require_tool katana && katana \
        -list "$BASE/recon/live_urls.txt" \
        -depth "$KATANA_DEPTH" \
        -silent \
        -jc \
        -kf all \
        -no-color \
        -ef png,jpg,gif,ico,css,woff,ttf,svg,webp \
        ${PROXY:+-proxy "$PROXY"} \
        -o "$BASE/recon/crawled.txt" 2>/dev/null || true

    # Merge and Deduplicate (Crucial Step)
    # Using 'sort -u' directly ensures all_urls.txt is clean
    cat "$BASE/recon/urls.txt" "$BASE/recon/crawled.txt" 2>/dev/null \
        | sort -u > "$BASE/recon/all_urls.txt"
    
    CRAWL_COUNT=$(count_lines "$BASE/recon/crawled.txt")
    TOTAL_COUNT=$(count_lines "$BASE/recon/all_urls.txt")
    log_ok "Crawled $CRAWL_COUNT new URLs | Total unique: $TOTAL_COUNT"
else
    log_warn "No live URLs to crawl — using historical data only"
    sort -u "$BASE/recon/urls.txt" > "$BASE/recon/all_urls.txt" 2>/dev/null || true
fi

# ── 7. Scope Check ───────────────────────────────────────────
# Remove out-of-scope URLs (different root domains)
if has_results "$BASE/recon/all_urls.txt"; then
    log_info "Filtering out-of-scope URLs..."

    # Escape dots in the target for safe Regex (e.g., example.com -> example\.com)
    SAFE_TARGET=$(echo "$TARGET" | sed 's/\./\\./g')

    # 1. LC_ALL=C for speed
    # 2. Match http(s)://
    # 3. Match optional subdomains ([a-z0-9.-]+\.)?
    # 4. Match the literal target and ensure it's followed by port, path, or end of line
    LC_ALL=C grep -Ei "^https?://([a-z0-9.-]+\.)?${SAFE_TARGET}(:[0-9]+)?([/]|(\?.*)|$)" \
        "$BASE/recon/all_urls.txt" | sort -u > "$BASE/recon/in_scope_urls.txt" || true

    # Clean up the raw file to save space if needed
    # rm "$BASE/recon/all_urls.txt" 
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
log_ok "Recon Summary:"
log_ok "  Subdomains   : $(count_lines "$BASE/recon/subdomains.txt")"
log_ok "  Live Hosts   : $(count_lines "$BASE/recon/live_hosts.txt")"
log_ok "  Total URLs   : $(count_lines "$BASE/recon/all_urls.txt")"
log_ok "  In-Scope URLs: $(count_lines "$BASE/recon/in_scope_urls.txt")"
