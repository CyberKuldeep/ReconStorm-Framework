#!/bin/bash
# =============================================================
#  ReconStorm — Module: Scanning
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

log_step "Scanning Module: $TARGET"
mkdir -p "$BASE/scan" "$BASE/tmp"

# ── 1. Resolve Target to IP ───────────────────────────────────
if [[ "$TYPE" == "domain" ]]; then
    log_info "Resolving $TARGET..."
    IP=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | head -n1)
    if [[ -z "$IP" ]]; then
        # Try with host command as fallback
        IP=$(host "$TARGET" 2>/dev/null | grep "has address" | head -n1 | awk '{print $NF}')
    fi
    if [[ -z "$IP" ]]; then
        log_error "Could not resolve $TARGET to IP"
        exit 1
    fi
    log_ok "Resolved: $TARGET → $IP"
    echo "$IP" > "$BASE/scan/target_ip.txt"
    echo "$TARGET" > "$BASE/scan/target_domain.txt"
else
    IP="$TARGET"
    echo "$IP" > "$BASE/scan/target_ip.txt"
fi

# ── 2. Check for Root (needed by masscan/naabu raw sockets) ──
IS_ROOT=0
if [[ $EUID -eq 0 ]]; then
    IS_ROOT=1
    log_ok "Running as root — full port scanning available"
else
    log_warn "Not root — masscan disabled (needs raw sockets). Using naabu connect-scan."
fi

# ── 3. Fast Port Discovery ────────────────────────────────────
OPEN_PORTS=""

# Naabu — works without root via connect-scan (-s c flag)
if require_tool naabu; then
    log_info "Running Naabu fast scan..."
    naabu_flags="-host $IP -top-ports 1000 -silent -o $BASE/scan/naabu.txt"
    [[ "$IS_ROOT" -eq 0 ]] && naabu_flags+=" -s c"  # connect-scan fallback

    run_safe 120 naabu $naabu_flags 2>/dev/null || true
fi

# Masscan — full range, root only
if [[ "$IS_ROOT" -eq 1 ]] && require_tool masscan; then
    log_info "Running Masscan full port scan (rate=$MASSCAN_RATE)..."
    run_safe 300 masscan \
        -p1-65535 "$IP" \
        --rate "$MASSCAN_RATE" \
        --output-format grepable \
        --output-filename "$BASE/scan/masscan.txt" 2>/dev/null || true

    # Extract and deduplicate open ports
    if has_results "$BASE/scan/masscan.txt"; then
        grep "Ports:" "$BASE/scan/masscan.txt" \
            | grep -oP '[0-9]+/open' \
            | cut -d'/' -f1 \
            | sort -un \
            | tr '\n' ',' \
            | sed 's/,$//' \
            > "$BASE/scan/masscan_ports.txt" || true
    fi
fi

# ── 4. Build Consolidated Port List ───────────────────────────
{
    # From naabu (one port per line)
    [[ -f "$BASE/scan/naabu.txt" ]] && cat "$BASE/scan/naabu.txt" 2>/dev/null
    # From masscan (comma-separated, split to one per line)
    [[ -f "$BASE/scan/masscan_ports.txt" ]] && \
        tr ',' '\n' < "$BASE/scan/masscan_ports.txt" 2>/dev/null
} | grep -E '^[0-9]+$' | sort -un > "$BASE/scan/open_ports.txt" || true

PORT_COUNT=$(count_lines "$BASE/scan/open_ports.txt")
log_ok "Discovered $PORT_COUNT open ports"

if [[ "$PORT_COUNT" -gt 0 ]]; then
    OPEN_PORTS=$(tr '\n' ',' < "$BASE/scan/open_ports.txt" | sed 's/,$//')
    log_info "Ports: $OPEN_PORTS"
fi

# ── 5. Nmap Deep Scan ─────────────────────────────────────────
if ! require_tool nmap; then
    log_warn "nmap not found — skipping deep scan"
else
    log_info "Running Nmap service/version detection..."

    # Choose port target
    if [[ -n "$OPEN_PORTS" ]]; then
        PORT_ARG="-p $OPEN_PORTS"
        log_info "Using discovered ports from Naabu/Masscan"
    else
        PORT_ARG="--top-ports 1000"
        log_warn "No prior port data — falling back to top-1000"
    fi

    # Scan flags — use -sS if root (SYN), -sT if not (connect)
    if [[ "$IS_ROOT" -eq 1 ]]; then
        SCAN_TYPE="-sS"
    else
        SCAN_TYPE="-sT"
    fi

    run_safe 600 nmap \
        $SCAN_TYPE -sV -sC \
        -T4 \
        --version-intensity 7 \
        $PORT_ARG \
        -oN "$BASE/scan/nmap.txt" \
        -oX "$BASE/scan/nmap.xml" \
        "$IP" 2>/dev/null || true

    # Parse nmap XML for structured service data
    if has_results "$BASE/scan/nmap.xml"; then
        grep -oP 'portid="\K[^"]+|name="\K[^"]+|product="\K[^"]+|version="\K[^"]+' \
            "$BASE/scan/nmap.xml" 2>/dev/null > "$BASE/scan/services_raw.txt" || true
    fi

    log_ok "Nmap scan complete"
fi

# ── 6. Parse Services for Downstream Use ──────────────────────
log_info "Parsing service fingerprints..."

if has_results "$BASE/scan/nmap.txt"; then
    # Extract: port, state, service, version
    grep -E "^[0-9]+/(tcp|udp)\s+open" "$BASE/scan/nmap.txt" \
        > "$BASE/scan/open_services.txt" || true

    # Flag interesting services for exploitation module
    grep -iE "ftp|ssh|telnet|smtp|rdp|vnc|mysql|postgres|mongodb|redis|elastic|jenkins|jboss|tomcat|phpmyadmin" \
        "$BASE/scan/open_services.txt" \
        > "$BASE/scan/interesting_services.txt" || true

    log_ok "Open services : $(count_lines "$BASE/scan/open_services.txt")"
    log_ok "Interesting   : $(count_lines "$BASE/scan/interesting_services.txt")"
fi

# ── 7. HTTP Service Check via httpx (if web ports found) ──────
if has_results "$BASE/scan/open_ports.txt"; then
    # Check common web ports for HTTP services on IP targets
    WEB_PORTS=("80" "443" "8080" "8443" "8888" "3000" "5000" "9090" "4443")
    WEB_TARGETS=()
    while IFS= read -r port; do
        for wp in "${WEB_PORTS[@]}"; do
            [[ "$port" == "$wp" ]] && WEB_TARGETS+=("http://$IP:$port")
        done
    done < "$BASE/scan/open_ports.txt"

    if [[ ${#WEB_TARGETS[@]} -gt 0 ]] && require_tool httpx; then
        log_info "Probing web services on discovered ports..."
        printf '%s\n' "${WEB_TARGETS[@]}" > "$BASE/tmp/web_targets.txt"
        httpx -l "$BASE/tmp/web_targets.txt" \
            -threads 20 \
            -status-code -title -tech-detect \
            -silent \
            -o "$BASE/scan/web_services.txt" 2>/dev/null || true

        # Merge with recon live_hosts if exists
        if [[ -f "$BASE/recon/live_hosts.txt" ]]; then
            merge_files "$BASE/recon/live_hosts.txt" \
                "$BASE/recon/live_hosts.txt" \
                "$BASE/scan/web_services.txt" 2>/dev/null || true
        else
            mkdir -p "$BASE/recon"
            cp "$BASE/scan/web_services.txt" "$BASE/recon/live_hosts.txt" 2>/dev/null || true
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
log_ok "Scanning Summary:"
log_ok "  Target IP      : $IP"
log_ok "  Open Ports     : $(count_lines "$BASE/scan/open_ports.txt")"
log_ok "  Open Services  : $(count_lines "$BASE/scan/open_services.txt" 2>/dev/null || echo 0)"
log_ok "  Interesting Svc: $(count_lines "$BASE/scan/interesting_services.txt" 2>/dev/null || echo 0)"
