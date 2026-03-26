#!/bin/bash
# =============================================================
#  ReconStorm Framework — Main Runner
#  Usage: ./ReconStorm.sh <domain|IP> [--modules recon,scan,...]
# =============================================================
set -uo pipefail

# ── Source config & helpers ──────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config/config.sh"
source "$SCRIPT_DIR/lib/logger.sh"
source "$SCRIPT_DIR/lib/utils.sh"

# ── Argument parsing ─────────────────────────────────────────
target="${1:-}"
shift || true

MODULES_FILTER=""
SKIP_CONFIRM=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --modules) MODULES_FILTER="$2"; shift 2 ;;
        -y|--yes)  SKIP_CONFIRM=1;      shift   ;;
        *) log_warn "Unknown flag: $1"; shift   ;;
    esac
done

# ── Input validation ─────────────────────────────────────────
if [[ -z "$target" ]]; then
    echo "Usage: ./ReconStorm.sh <domain|IP> [--modules recon,scan,enum,vuln,exploit] [-y]"
    exit 1
fi

# Sanitize target (prevent path traversal / injection)
if [[ "$target" =~ [^a-zA-Z0-9._:-] ]]; then
    echo "[!] Invalid target format: $target"
    exit 1
fi

# ── Target type detection ─────────────────────────────────────
if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    TYPE="ip"
else
    TYPE="domain"
fi

# ── Output directory setup ────────────────────────────────────
timestamp=$(date +%F_%H%M%S)
BASE_DIR="${OUTPUT_DIR}/${target}-${timestamp}"
mkdir -p "$BASE_DIR"/{recon,scan,enum,vuln,exploit,logs,tmp,report}

LOGFILE="$BASE_DIR/logs/run.log"
START_TIME=$(date +%s)

# ── Redirect all output to tee (log + stdout) ─────────────────
exec > >(tee -a "$LOGFILE") 2>&1

# ── Cleanup trap (CTRL+C / kill) ─────────────────────────────
cleanup() {
    echo ""
    log_warn "Interrupted — cleaning up background jobs..."
    jobs -p | xargs -r kill 2>/dev/null
    log_info "Partial results saved to: $BASE_DIR"
    exit 130
}
trap cleanup INT TERM

# ── Banner ────────────────────────────────────────────────────
print_banner() {
cat <<'EOF'
  ____  _____ ____ ___  _   _ ____ _____ ___  ____  __  __
 |  _ \| ____/ ___/ _ \| \ | / ___|_   _/ _ \|  _ \|  \/  |
 | |_) |  _|| |  | | | |  \| \___ \ | || | | | |_) | |\/| |
 |  _ <| |__| |__| |_| | |\  |___) || || |_| |  _ <| |  | |
 |_| \_\_____\____\___/|_| \_|____/ |_| \___/|_| \_\_|  |_|
EOF
    echo "                        v2.0 — Advanced Recon Framework"
    echo "══════════════════════════════════════════════════════════"
}
print_banner

log_info "Target   : $target"
log_info "Type     : $TYPE"
log_info "Output   : $BASE_DIR"
log_info "Started  : $(date '+%Y-%m-%d %H:%M:%S')"
echo "══════════════════════════════════════════════════════════"

# ── Export vars for child modules ─────────────────────────────
export TARGET="$target"
export BASE_DIR TYPE LOGFILE
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin:/usr/local/bin"

# ── Tool availability check ───────────────────────────────────
MISSING_TOOLS=()
check_tools() {
    local required=("$@")
    for tool in "${required[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "Found: $tool"
        else
            log_warn "Missing: $tool"
            MISSING_TOOLS+=("$tool")
        fi
    done
}

log_info "Checking tools..."
check_tools subfinder httpx nuclei nmap naabu masscan gau katana \
            dalfox sqlmap nikto ffuf dirsearch subzy gowitness \
            assetfinder amass gf searchsploit

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    log_warn "Missing tools: ${MISSING_TOOLS[*]}"
    log_warn "Run ./install.sh to install missing dependencies."
    if [[ "$SKIP_CONFIRM" -eq 0 ]]; then
        read -rp "[?] Continue anyway? (y/N): " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { log_info "Aborted."; exit 0; }
    fi
fi

# ── Module runner ─────────────────────────────────────────────
MODULE_STATUS=()

run_module() {
    local name="$1"
    local script="$2"
    local mod_key="${name,,}"  # lowercase key

    # Filter check
    if [[ -n "$MODULES_FILTER" ]] && ! echo "$MODULES_FILTER" | grep -qw "$mod_key"; then
        log_info "Skipping $name (not in --modules filter)"
        return
    fi

    if [[ ! -f "$SCRIPT_DIR/modules/$script" ]]; then
        log_error "Module missing: modules/$script"
        MODULE_STATUS+=("$name:MISSING")
        return
    fi

    echo ""
    echo "══════════════════════════════════════════════════════════"
    log_info "Starting: $name"
    local t_start=$(date +%s)

    if bash "$SCRIPT_DIR/modules/$script" "$target" "$BASE_DIR" "$TYPE"; then
        local t_end=$(date +%s)
        local elapsed=$((t_end - t_start))
        log_ok "$name completed in ${elapsed}s"
        MODULE_STATUS+=("$name:OK(${elapsed}s)")
    else
        log_error "$name failed — continuing..."
        MODULE_STATUS+=("$name:FAILED")
    fi
}

# ── Execution flow ────────────────────────────────────────────
if [[ "$TYPE" == "domain" ]]; then
    run_module "recon"       "recon.sh"
else
    log_info "Skipping recon module (IP target)"
fi

run_module "scan"        "scanning.sh"
run_module "enum"        "enumeration.sh"
run_module "vuln"        "vulnscan.sh"
run_module "exploit"     "exploitation.sh"

# ── Generate final summary report ────────────────────────────
bash "$SCRIPT_DIR/lib/report.sh" "$BASE_DIR" "$target" "$TYPE"

# ── Final summary ─────────────────────────────────────────────
TOTAL_TIME=$(( $(date +%s) - START_TIME ))
echo ""
echo "══════════════════════════════════════════════════════════"
log_ok  "ReconStorm Completed in ${TOTAL_TIME}s"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "  Module Summary:"
for status in "${MODULE_STATUS[@]}"; do
    name="${status%%:*}"
    state="${status##*:}"
    if [[ "$state" == FAILED ]]; then
        log_error "  ✘ $name — $state"
    elif [[ "$state" == MISSING ]]; then
        log_warn  "  ⚠ $name — $state"
    else
        log_ok    "  ✔ $name — $state"
    fi
done

echo ""
log_info "Output  : $BASE_DIR"
log_info "Report  : $BASE_DIR/report/summary.md"
log_info "Logs    : $LOGFILE"
echo "══════════════════════════════════════════════════════════"
