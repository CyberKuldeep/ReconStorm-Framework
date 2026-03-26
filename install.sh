#!/bin/bash
# =============================================================
#  ReconStorm Framework — Installer
#  Supports: Ubuntu/Debian, Kali Linux, Parrot OS
#  Usage : sudo ./install.sh [--skip-upgrade] [--tools-only]
#  Flags :
#    --skip-upgrade   skip apt upgrade (safe for existing systems)
#    --tools-only     skip apt packages, only install Go/Py tools
#    --resume         skip already-installed tools
# =============================================================

# ── Safety: do NOT use set -e — we handle errors per-tool ────
set -uo pipefail

# ── Must NOT be root for Go/Rust tools (but need sudo for apt) ─
if [[ $EUID -eq 0 ]]; then
    echo "[!] Do not run as root. Use a normal user with sudo access."
    echo "    Go and Rust tools must install to your home directory."
    exit 1
fi

# ── Parse flags ───────────────────────────────────────────────
SKIP_UPGRADE=0
TOOLS_ONLY=0
RESUME=0

for arg in "$@"; do
    case "$arg" in
        --skip-upgrade) SKIP_UPGRADE=1 ;;
        --tools-only)   TOOLS_ONLY=1   ;;
        --resume)       RESUME=1        ;;
    esac
done

# ── Dirs ──────────────────────────────────────────────────────
TOOLS_DIR="$HOME/tools"
LOG_FILE="$HOME/reconstorm_install.log"
STATE_FILE="$HOME/.reconstorm_install_state"

mkdir -p "$TOOLS_DIR"

# ── Logger ────────────────────────────────────────────────────
_R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
_B='\033[0;34m' _C='\033[0;36m' _N='\033[0m'

log_info()  { echo -e "${_C}[INFO]${_N}  $*" | tee -a "$LOG_FILE"; }
log_ok()    { echo -e "${_G}[ OK ]${_N}  $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${_Y}[WARN]${_N}  $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${_R}[ERR ]${_N}  $*" | tee -a "$LOG_FILE"; }
log_step()  { echo -e "\n${_B}[>>>]${_N}  $*" | tee -a "$LOG_FILE"; }

# ── State tracking (resume support) ──────────────────────────
mark_done()  { echo "$1" >> "$STATE_FILE"; }
is_done()    { [[ "$RESUME" -eq 1 ]] && grep -qx "$1" "$STATE_FILE" 2>/dev/null; }

# ── Stats tracking ────────────────────────────────────────────
INSTALLED=0
SKIPPED=0
FAILED=0
FAILED_LIST=()

record_ok()   { ((INSTALLED++)); mark_done "$1"; }
record_skip() { ((SKIPPED++)); }
record_fail() { ((FAILED++)); FAILED_LIST+=("$1"); log_error "FAILED: $1"; }

# ── OS Detection ─────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-}"
    else
        OS_ID="unknown"
    fi

    case "$OS_ID" in
        kali|parrot|debian|ubuntu|linuxmint)
            PKG_MGR="apt"
            ;;
        *)
            if echo "$OS_LIKE" | grep -qE "debian|ubuntu"; then
                PKG_MGR="apt"
            else
                log_error "Unsupported OS: $OS_ID"
                log_error "This installer supports Debian/Ubuntu/Kali/Parrot."
                exit 1
            fi
            ;;
    esac
    log_ok "Detected OS: $OS_ID (package manager: $PKG_MGR)"
}

# ── Disk space check ─────────────────────────────────────────
check_disk_space() {
    local required_gb=5
    local available_kb
    available_kb=$(df "$HOME" | awk 'NR==2 {print $4}')
    local available_gb=$(( available_kb / 1024 / 1024 ))

    if [[ $available_gb -lt $required_gb ]]; then
        log_warn "Low disk space: ${available_gb}GB available, ${required_gb}GB recommended."
        read -rp "[?] Continue anyway? (y/N): " ans
        [[ "$ans" =~ ^[Yy]$ ]] || exit 0
    else
        log_ok "Disk space: ${available_gb}GB available"
    fi
}

# ── PATH helper ───────────────────────────────────────────────
add_to_path() {
    local p="$1"
    # Add to current session
    export PATH="$PATH:$p"

    # Add to shell rc files (idempotent)
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        [[ -f "$rc" ]] || continue
        if ! grep -qF "$p" "$rc"; then
            echo "export PATH=\"\$PATH:$p\"" >> "$rc"
            log_ok "Added $p to $rc"
        fi
    done
}

# ── Safe apt install (never kills script on failure) ──────────
apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" &>/dev/null; then
        log_ok "Already installed: $pkg"
        record_skip "$pkg"
        return
    fi
    if sudo apt-get install -y --no-install-recommends "$pkg" \
            >> "$LOG_FILE" 2>&1; then
        log_ok "Installed: $pkg"
        record_ok "apt:$pkg"
    else
        log_warn "apt failed for: $pkg — trying snap fallback..."
        if snap install "$pkg" >> "$LOG_FILE" 2>&1; then
            log_ok "Installed via snap: $pkg"
            record_ok "snap:$pkg"
        else
            record_fail "apt:$pkg"
        fi
    fi
}

# ── Go install helper ─────────────────────────────────────────
go_install() {
    local module="$1"
    local binary="${2:-$(basename "$module" | cut -d'@' -f1)}"

    if is_done "go:$binary"; then
        log_ok "Skipping (already done): $binary"
        record_skip "go:$binary"
        return
    fi

    if command -v "$binary" &>/dev/null && [[ "$RESUME" -eq 1 ]]; then
        log_ok "Already in PATH: $binary"
        record_skip "go:$binary"
        return
    fi

    log_info "go install: $binary"
    if go install "${module}@latest" >> "$LOG_FILE" 2>&1; then
        log_ok "Installed: $binary"
        record_ok "go:$binary"
    else
        record_fail "go:$binary"
    fi
}

# ── Python venv tool installer ────────────────────────────────
py_venv_install() {
    local name="$1"
    local repo="$2"
    local reqs="${3:-requirements.txt}"
    local dir="$TOOLS_DIR/$name"
    local venv="$TOOLS_DIR/${name}-venv"
    local wrapper="/usr/local/bin/${name,,}"

    if is_done "py:$name"; then
        log_ok "Skipping (already done): $name"
        record_skip "py:$name"
        return
    fi

    # Clone if not exists
    if [[ ! -d "$dir" ]]; then
        log_info "Cloning $name..."
        if ! git clone "$repo" "$dir" >> "$LOG_FILE" 2>&1; then
            record_fail "py:$name (clone failed)"
            return
        fi
    fi

    # Create venv and install deps
    python3 -m venv "$venv" >> "$LOG_FILE" 2>&1
    if [[ -f "$dir/$reqs" ]]; then
        "$venv/bin/pip" install -q -r "$dir/$reqs" >> "$LOG_FILE" 2>&1 || true
    fi
    "$venv/bin/pip" install -q -e "$dir" >> "$LOG_FILE" 2>&1 || true

    # Create system-wide wrapper so the tool is callable by name
    sudo tee "$wrapper" > /dev/null <<WRAPPER
#!/bin/bash
exec "$venv/bin/python3" "$dir/$(basename "$dir" | tr '[:upper:]' '[:lower:]').py" "\$@"
WRAPPER
    sudo chmod +x "$wrapper"

    log_ok "Installed: $name → $wrapper"
    record_ok "py:$name"
}

# ── Git clone tool (no install, just needs to exist) ──────────
git_tool() {
    local name="$1"
    local repo="$2"
    local dir="$TOOLS_DIR/$name"

    if is_done "git:$name"; then
        log_ok "Skipping (already done): $name"
        record_skip "git:$name"
        return
    fi

    if [[ -d "$dir" ]]; then
        log_info "Updating: $name"
        git -C "$dir" pull --ff-only >> "$LOG_FILE" 2>&1 || true
    else
        log_info "Cloning: $name"
        if ! git clone "$repo" "$dir" >> "$LOG_FILE" 2>&1; then
            record_fail "git:$name"
            return
        fi
    fi
    log_ok "Ready: $name → $dir"
    record_ok "git:$name"
}

# =============================================================
#  BANNER
# =============================================================
clear
cat <<'BANNER'
  ____  _____ ____ ___  _   _ ____ _____ ___  ____  __  __
 |  _ \| ____/ ___/ _ \| \ | / ___|_   _/ _ \|  _ \|  \/  |
 | |_) |  _|| |  | | | |  \| \___ \ | || | | | |_) | |\/| |
 |  _ <| |__| |__| |_| | |\  |___) || || |_| |  _ <| |  | |
 |_| \_\_____\____\___/|_| \_|____/ |_| \___/|_| \_\_|  |_|
                        Installer v2.0
BANNER
echo "  Log file : $LOG_FILE"
echo "  State    : $STATE_FILE"
[[ "$RESUME" -eq 1 ]] && echo "  Mode     : RESUME (skipping completed steps)"
echo ""

# =============================================================
#  PRE-FLIGHT CHECKS
# =============================================================
log_step "Pre-flight checks"
detect_os
check_disk_space

# Check sudo works
if ! sudo -n true 2>/dev/null; then
    log_info "Sudo password required for system packages"
    sudo -v || { log_error "sudo failed"; exit 1; }
fi

# =============================================================
#  STEP 1 — SYSTEM PACKAGES
# =============================================================
if [[ "$TOOLS_ONLY" -eq 0 ]]; then
    log_step "Step 1/6 — System packages"

    log_info "Updating package lists..."
    sudo apt-get update -y >> "$LOG_FILE" 2>&1

    if [[ "$SKIP_UPGRADE" -eq 0 ]]; then
        log_info "Upgrading installed packages (use --skip-upgrade to skip)..."
        sudo apt-get upgrade -y >> "$LOG_FILE" 2>&1 || log_warn "Upgrade had warnings — continuing"
    fi

    BASE_PKGS=(
        git curl wget jq whois dnsutils
        build-essential libpcap-dev unzip
        nmap masscan
        nikto sqlmap
        python3 python3-pip python3-venv pipx
        snapd
        whatweb wafw00f
        dnsrecon gobuster feroxbuster
        theharvester
    )

    # Chromium: name differs by distro
    if apt-cache show chromium &>/dev/null; then
        BASE_PKGS+=(chromium)
    elif apt-cache show chromium-browser &>/dev/null; then
        BASE_PKGS+=(chromium-browser)
    else
        log_warn "Chromium not found in apt — screenshots may not work"
    fi

    # ffuf: prefer apt if recent enough, else use go install below
    if apt-cache show ffuf &>/dev/null; then
        BASE_PKGS+=(ffuf)
    fi

    # dirsearch: may not exist in all repos
    if apt-cache show dirsearch &>/dev/null; then
        BASE_PKGS+=(dirsearch)
    fi

    # SecLists (large — separate)
    if apt-cache show seclists &>/dev/null; then
        BASE_PKGS+=(seclists)
    fi

    for pkg in "${BASE_PKGS[@]}"; do
        apt_install "$pkg"
    done
fi

# =============================================================
#  STEP 2 — GO INSTALLATION
# =============================================================
log_step "Step 2/6 — Go language"

install_go() {
    local required_major=1
    local required_minor=21

    # Check existing Go version
    if command -v go &>/dev/null; then
        local current
        current=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' | head -n1)
        local cur_major cur_minor
        cur_major=$(echo "$current" | cut -d. -f1)
        cur_minor=$(echo "$current" | cut -d. -f2)

        if [[ "$cur_major" -gt "$required_major" ]] || \
           [[ "$cur_major" -eq "$required_major" && "$cur_minor" -ge "$required_minor" ]]; then
            log_ok "Go $current already installed and up to date"
            add_to_path "/usr/local/go/bin"
            export GOPATH="$HOME/go"
            mkdir -p "$GOPATH/bin"
            add_to_path "$GOPATH/bin"
            return
        fi
        log_warn "Go $current is outdated — upgrading..."
    fi

    # Fetch latest stable version
    local go_version
    go_version=$(curl -s --max-time 10 "https://go.dev/VERSION?m=text" | head -n1)
    if [[ -z "$go_version" ]]; then
        log_error "Could not fetch Go version from go.dev"
        return 1
    fi

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armv6l" ;;
        *) log_error "Unsupported arch: $arch"; return 1 ;;
    esac

    local tarfile="${go_version}.linux-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarfile}"

    log_info "Downloading $go_version ($arch)..."
    wget -q --show-progress "$url" -O "/tmp/$tarfile"

    # Verify checksum
    local expected_sha
    expected_sha=$(curl -s "https://go.dev/dl/?mode=json" | \
        python3 -c "
import json,sys
d=json.load(sys.stdin)
for v in d:
    for f in v.get('files',[]):
        if f.get('filename')=='$tarfile':
            print(f.get('sha256',''))
            break
" 2>/dev/null)

    if [[ -n "$expected_sha" ]]; then
        local actual_sha
        actual_sha=$(sha256sum "/tmp/$tarfile" | awk '{print $1}')
        if [[ "$actual_sha" != "$expected_sha" ]]; then
            log_error "SHA256 mismatch for Go tarball — aborting"
            rm -f "/tmp/$tarfile"
            return 1
        fi
        log_ok "SHA256 verified"
    else
        log_warn "Could not verify checksum — proceeding anyway"
    fi

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$tarfile"
    rm -f "/tmp/$tarfile"

    add_to_path "/usr/local/go/bin"
    export GOPATH="$HOME/go"
    mkdir -p "$GOPATH/bin"
    add_to_path "$GOPATH/bin"

    log_ok "Go $(go version) installed"
}

install_go

# =============================================================
#  STEP 3 — GO TOOLS
# =============================================================
log_step "Step 3/6 — Go security tools"

# NOTE: Updated to latest module paths (v3 where applicable)
GO_TOOLS=(
    # Subdomain enumeration
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder:subfinder"
    "github.com/tomnomnom/assetfinder:assetfinder"
    "github.com/gwen001/github-subdomains:github-subdomains"
    "github.com/projectdiscovery/uncover/cmd/uncover:uncover"

    # HTTP probing
    "github.com/projectdiscovery/httpx/cmd/httpx:httpx"

    # Crawling & URL collection
    "github.com/projectdiscovery/katana/cmd/katana:katana"
    "github.com/lc/gau/v2/cmd/gau:gau"
    "github.com/tomnomnom/waybackurls:waybackurls"
    "github.com/hakluke/hakrawler:hakrawler"

    # Port scanning
    "github.com/projectdiscovery/naabu/v2/cmd/naabu:naabu"

    # DNS tools
    "github.com/projectdiscovery/dnsx/cmd/dnsx:dnsx"
    "github.com/projectdiscovery/tlsx/cmd/tlsx:tlsx"

    # Vulnerability scanning
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei:nuclei"

    # XSS
    "github.com/hahwul/dalfox/v2:dalfox"

    # Pattern matching & URL manipulation
    "github.com/tomnomnom/gf:gf"
    "github.com/tomnomnom/qsreplace:qsreplace"
    "github.com/tomnomnom/anew:anew"
    "github.com/tomnomnom/unfurl:unfurl"
    "github.com/tomnomnom/httprobe:httprobe"

    # Subdomain takeover
    "github.com/PentestPad/subzy:subzy"

    # Screenshots
    "github.com/sensepost/gowitness:gowitness"

    # Directory fuzzing (latest ffuf from source)
    "github.com/ffuf/ffuf/v2:ffuf"
)

for entry in "${GO_TOOLS[@]}"; do
    module="${entry%%:*}"
    binary="${entry##*:}"
    go_install "$module" "$binary"
done

# =============================================================
#  STEP 4 — RUST TOOLS
# =============================================================
log_step "Step 4/6 — Rust tools"

install_rust_and_tools() {
    # Install rustup if not present
    if ! command -v cargo &>/dev/null; then
        log_info "Installing Rust via rustup..."

        # Download and verify
        curl --proto '=https' --tlsv1.2 -sSf \
            "https://sh.rustup.rs" -o /tmp/rustup-init.sh

        # Basic sanity check (not empty, is a shell script)
        if ! head -1 /tmp/rustup-init.sh | grep -q "^#!"; then
            log_error "rustup-init.sh looks invalid — aborting Rust install"
            return 1
        fi

        sh /tmp/rustup-init.sh -y --no-modify-path >> "$LOG_FILE" 2>&1
        rm -f /tmp/rustup-init.sh

        # Source cargo for current session
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        add_to_path "$HOME/.cargo/bin"
    else
        log_ok "Rust/cargo already installed"
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi

    # Install rustscan
    if is_done "rust:rustscan"; then
        log_ok "Skipping (already done): rustscan"
        record_skip "rust:rustscan"
        return
    fi

    if command -v rustscan &>/dev/null && [[ "$RESUME" -eq 1 ]]; then
        log_ok "Already installed: rustscan"
        record_skip "rust:rustscan"
        return
    fi

    log_info "Installing rustscan..."
    if cargo install rustscan >> "$LOG_FILE" 2>&1; then
        log_ok "Installed: rustscan"
        record_ok "rust:rustscan"
    else
        # Fallback: try GitHub releases binary
        log_warn "cargo install failed — trying GitHub release..."
        local rs_version
        rs_version=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
            | jq -r '.tag_name' 2>/dev/null)
        if [[ -n "$rs_version" ]]; then
            wget -q "https://github.com/RustScan/RustScan/releases/download/${rs_version}/rustscan_${rs_version#v}_amd64.deb" \
                -O /tmp/rustscan.deb && \
            sudo dpkg -i /tmp/rustscan.deb >> "$LOG_FILE" 2>&1 && \
            rm -f /tmp/rustscan.deb && \
            log_ok "Installed rustscan via .deb" && \
            record_ok "rust:rustscan" || \
            record_fail "rust:rustscan"
        else
            record_fail "rust:rustscan"
        fi
    fi
}

install_rust_and_tools

# =============================================================
#  STEP 5 — PYTHON TOOLS
# =============================================================
log_step "Step 5/6 — Python tools"

# pipx — safer than pip install --user for CLI tools
if ! command -v pipx &>/dev/null; then
    python3 -m pip install --user pipx >> "$LOG_FILE" 2>&1
    python3 -m pipx ensurepath >> "$LOG_FILE" 2>&1
    add_to_path "$HOME/.local/bin"
fi

pipx_install() {
    local pkg="$1"
    local binary="${2:-$1}"

    if is_done "pipx:$pkg"; then
        log_ok "Skipping (already done): $pkg"
        record_skip "pipx:$pkg"
        return
    fi

    if pipx install "$pkg" >> "$LOG_FILE" 2>&1; then
        log_ok "Installed: $pkg"
        record_ok "pipx:$pkg"
    else
        record_fail "pipx:$pkg"
    fi
}

pipx_install droopescan
pipx_install wfuzz

# LinkFinder — needs custom wrapper
if ! is_done "py:LinkFinder"; then
    log_info "Installing LinkFinder..."
    if [[ ! -d "$TOOLS_DIR/LinkFinder" ]]; then
        git clone https://github.com/GerbenJavado/LinkFinder.git \
            "$TOOLS_DIR/LinkFinder" >> "$LOG_FILE" 2>&1
    fi
    python3 -m venv "$TOOLS_DIR/linkfinder-venv" >> "$LOG_FILE" 2>&1
    "$TOOLS_DIR/linkfinder-venv/bin/pip" install -q \
        -r "$TOOLS_DIR/LinkFinder/requirements.txt" >> "$LOG_FILE" 2>&1 || true

    # Create callable wrapper
    sudo tee /usr/local/bin/linkfinder > /dev/null <<'WRAPPER'
#!/bin/bash
exec "$HOME/tools/linkfinder-venv/bin/python3" \
     "$HOME/tools/LinkFinder/linkfinder.py" "$@"
WRAPPER
    # Expand HOME properly in wrapper
    sudo sed -i "s|\$HOME|$HOME|g" /usr/local/bin/linkfinder
    sudo chmod +x /usr/local/bin/linkfinder
    log_ok "LinkFinder installed → linkfinder"
    record_ok "py:LinkFinder"
else
    log_ok "Skipping (already done): LinkFinder"
fi

# SecretFinder
if ! is_done "py:SecretFinder"; then
    log_info "Installing SecretFinder..."
    if [[ ! -d "$TOOLS_DIR/SecretFinder" ]]; then
        git clone https://github.com/m4ll0k/SecretFinder.git \
            "$TOOLS_DIR/SecretFinder" >> "$LOG_FILE" 2>&1
    fi
    python3 -m venv "$TOOLS_DIR/secretfinder-venv" >> "$LOG_FILE" 2>&1
    "$TOOLS_DIR/secretfinder-venv/bin/pip" install -q \
        -r "$TOOLS_DIR/SecretFinder/requirements.txt" >> "$LOG_FILE" 2>&1 || true

    sudo tee /usr/local/bin/secretfinder > /dev/null <<'WRAPPER'
#!/bin/bash
exec "$HOME/tools/secretfinder-venv/bin/python3" \
     "$HOME/tools/SecretFinder/SecretFinder.py" "$@"
WRAPPER
    sudo sed -i "s|\$HOME|$HOME|g" /usr/local/bin/secretfinder
    sudo chmod +x /usr/local/bin/secretfinder
    log_ok "SecretFinder installed → secretfinder"
    record_ok "py:SecretFinder"
else
    log_ok "Skipping (already done): SecretFinder"
fi

# =============================================================
#  STEP 6 — DATA: WORDLISTS, GF PATTERNS, NUCLEI TEMPLATES
# =============================================================
log_step "Step 6/6 — Wordlists, patterns & templates"

# SecLists
if [[ ! -d "/usr/share/seclists" ]]; then
    log_info "Installing SecLists (~900MB)..."
    if apt-cache show seclists &>/dev/null; then
        sudo apt-get install -y seclists >> "$LOG_FILE" 2>&1 && \
            log_ok "SecLists installed via apt" || {
            log_warn "apt install failed — cloning from GitHub..."
            sudo git clone --depth=1 \
                https://github.com/danielmiessler/SecLists.git \
                /usr/share/seclists >> "$LOG_FILE" 2>&1 && \
                log_ok "SecLists cloned" || \
                log_warn "SecLists install failed — install manually"
        }
    else
        sudo git clone --depth=1 \
            https://github.com/danielmiessler/SecLists.git \
            /usr/share/seclists >> "$LOG_FILE" 2>&1 && \
            log_ok "SecLists cloned" || \
            log_warn "SecLists install failed"
    fi
else
    log_ok "SecLists already exists"
fi

# testssl.sh
git_tool "testssl" "https://github.com/drwetter/testssl.sh.git"
if [[ -f "$TOOLS_DIR/testssl/testssl.sh" ]]; then
    sudo ln -sf "$TOOLS_DIR/testssl/testssl.sh" /usr/local/bin/testssl 2>/dev/null || true
fi

# GF patterns
log_info "Installing GF patterns..."
mkdir -p "$HOME/.gf"
GF_PATTERNS_DIR="$TOOLS_DIR/gf-patterns"
if [[ ! -d "$GF_PATTERNS_DIR" ]]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns.git \
        "$GF_PATTERNS_DIR" >> "$LOG_FILE" 2>&1
fi
cp "$GF_PATTERNS_DIR"/*.json "$HOME/.gf/" 2>/dev/null && \
    log_ok "GF patterns installed to ~/.gf/" || \
    log_warn "GF patterns: no JSON files found"

# tomnomnom gf examples
GF_EXAMPLES="$TOOLS_DIR/gf-examples"
if [[ ! -d "$GF_EXAMPLES" ]]; then
    git clone https://github.com/tomnomnom/gf.git "$GF_EXAMPLES" >> "$LOG_FILE" 2>&1
fi
cp "$GF_EXAMPLES"/examples/*.json "$HOME/.gf/" 2>/dev/null || true
log_ok "GF base patterns installed"

# Nuclei templates (v3 syntax)
if command -v nuclei &>/dev/null; then
    log_info "Updating Nuclei templates..."
    if nuclei -update-templates >> "$LOG_FILE" 2>&1; then
        log_ok "Nuclei templates updated"
    else
        # v3 uses -update flag
        nuclei -update >> "$LOG_FILE" 2>&1 && \
            log_ok "Nuclei templates updated (v3)" || \
            log_warn "Nuclei template update failed — run manually: nuclei -update-templates"
    fi
fi

# =============================================================
#  TOOL VERIFICATION
# =============================================================
log_step "Verification"

BINARY_TOOLS=(
    subfinder assetfinder httpx katana gau waybackurls
    naabu dnsx nuclei dalfox gf sqlmap nmap ffuf
    gowitness subzy rustscan
)

FILE_TOOLS=(
    "linkfinder:/usr/local/bin/linkfinder"
    "secretfinder:/usr/local/bin/secretfinder"
    "testssl:$TOOLS_DIR/testssl/testssl.sh"
    "seclists:/usr/share/seclists"
    "gf-patterns:$HOME/.gf/xss.json"
)

ALL_PASS=1

echo ""
echo "  Binary tools:"
for tool in "${BINARY_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${_G}[✔]${_N} $tool"
    else
        echo -e "  ${_R}[✘]${_N} $tool — NOT FOUND"
        ALL_PASS=0
    fi
done

echo ""
echo "  File/dir tools:"
for entry in "${FILE_TOOLS[@]}"; do
    name="${entry%%:*}"
    path="${entry##*:}"
    if [[ -e "$path" ]]; then
        echo -e "  ${_G}[✔]${_N} $name → $path"
    else
        echo -e "  ${_R}[✘]${_N} $name — NOT FOUND at $path"
        ALL_PASS=0
    fi
done

# =============================================================
#  FINAL SUMMARY
# =============================================================
echo ""
echo "══════════════════════════════════════════════════════════"
log_ok  "Installation Summary"
echo "══════════════════════════════════════════════════════════"
log_ok  "  Installed : $INSTALLED"
log_info "  Skipped   : $SKIPPED"

if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
    log_error "  Failed    : $FAILED"
    log_error "  Failed tools:"
    for f in "${FAILED_LIST[@]}"; do
        log_error "    - $f"
    done
    echo ""
    log_warn "Check $LOG_FILE for details on failures."
    log_warn "Re-run with --resume to retry only failed tools."
else
    log_ok  "  Failed    : 0"
fi

echo ""
if [[ "$ALL_PASS" -eq 1 ]]; then
    log_ok "All tools verified!"
else
    log_warn "Some tools are missing — check above and see $LOG_FILE"
fi

echo ""
echo "══════════════════════════════════════════════════════════"
log_ok "ReconStorm is ready."
echo ""
log_info "Next steps:"
echo "  1. Add API keys: nano config/api_keys.conf"
echo "  2. Reload shell:  source ~/.bashrc  (or ~/.zshrc)"
echo "  3. Run:           ./ReconStorm.sh <target>"
echo "══════════════════════════════════════════════════════════"
