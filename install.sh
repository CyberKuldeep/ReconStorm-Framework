#!/bin/bash

set -euo pipefail

echo "[+] Starting ReconStorm Installation 🔥"

# -----------------------------
# UPDATE SYSTEM
# -----------------------------
echo "[+] Updating system..."
sudo apt update -y && sudo apt upgrade -y

# -----------------------------
# INSTALL BASE DEPENDENCIES
# -----------------------------
echo "[+] Installing base dependencies..."

sudo apt install -y \
git curl wget jq whois dnsutils build-essential \
nmap masscan ffuf dirsearch nikto sqlmap \
python3 python3-pip python3-venv pipx \
golang-go libpcap-dev unzip snapd chromium \
amass whatweb wafw00f dnsrecon dnsenum \
gobuster feroxbuster seclists \
theharvester recon-ng \
wpscan joomscan

# -----------------------------
# FIX GO VERSION
# -----------------------------
echo "[+] Checking Go version..."

if ! go version | grep -q "1.25"; then
    echo "[+] Installing Go 1.25..."
    wget -q https://go.dev/dl/go1.25.8.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.25.8.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
fi

export PATH=$PATH:$(go env GOPATH)/bin

# -----------------------------
# INSTALL GO TOOLS
# -----------------------------
echo "[+] Installing Go tools..."

go_tools=(
"github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
"github.com/tomnomnom/assetfinder"
"github.com/projectdiscovery/uncover/cmd/uncover"
"github.com/gwen001/github-subdomains"

"github.com/projectdiscovery/httpx/cmd/httpx"
"github.com/hakluke/hakrawler"
"github.com/projectdiscovery/katana/cmd/katana"
"github.com/lc/gau/v2/cmd/gau"
"github.com/tomnomnom/waybackurls"

"github.com/projectdiscovery/naabu/v2/cmd/naabu"
"github.com/projectdiscovery/dnsx/cmd/dnsx"
"github.com/projectdiscovery/tlsx/cmd/tlsx"

"github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
"github.com/hahwul/dalfox/v2"

"github.com/tomnomnom/gf"
"github.com/tomnomnom/qsreplace"
"github.com/tomnomnom/anew"

"github.com/PentestPad/subzy"
"github.com/sensepost/gowitness"
)

for tool in "${go_tools[@]}"; do
    echo "[+] Installing $tool"
    go install "$tool@latest" || echo "[!] Failed: $tool"
done

# -----------------------------
# SMART SHELL DETECTION + PATH FIX
# -----------------------------
echo "[+] Detecting shell and fixing PATH..."

CURRENT_SHELL=$(basename "$SHELL")
GO_PATH="$HOME/go/bin"

add_path() {
    FILE=$1
    if ! grep -q "$GO_PATH" "$FILE" 2>/dev/null; then
        echo "export PATH=\$PATH:$GO_PATH" >> "$FILE"
        echo "[+] Added Go PATH to $FILE"
    else
        echo "[✔] PATH already exists in $FILE"
    fi
}

if [[ "$CURRENT_SHELL" == "bash" ]]; then
    add_path "$HOME/.bashrc"
    source "$HOME/.bashrc" || true

elif [[ "$CURRENT_SHELL" == "zsh" ]]; then
    add_path "$HOME/.zshrc"
    source "$HOME/.zshrc" || true

else
    echo "[!] Unknown shell, updating both..."
    add_path "$HOME/.bashrc"
    add_path "$HOME/.zshrc"
fi

# Apply immediately
export PATH=$PATH:$GO_PATH

echo "[✔] PATH configured successfully!"

# -----------------------------
# RUSTSCAN
# -----------------------------
echo "[+] Installing Rustscan..."

if ! command -v rustscan &> /dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    cargo install rustscan --force
fi

# -----------------------------
# PYTHON TOOLS
# -----------------------------
echo "[+] Installing Python tools..."

pipx ensurepath --force
pipx install droopescan || echo "[!] droopescan install skipped"

# -----------------------------
# JS ANALYSIS TOOLS
# -----------------------------
echo "[+] Installing JS analysis tools..."

mkdir -p ~/tools

if [ ! -d "$HOME/tools/LinkFinder" ]; then
    git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
fi

python3 -m venv ~/tools/linkfinder-venv
source ~/tools/linkfinder-venv/bin/activate
pip install -r ~/tools/LinkFinder/requirements.txt
deactivate

if [ ! -d "$HOME/tools/SecretFinder" ]; then
    git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
fi

python3 -m venv ~/tools/secretfinder-venv
source ~/tools/secretfinder-venv/bin/activate
pip install -r ~/tools/SecretFinder/requirements.txt
deactivate

# -----------------------------
# SSL SCANNER
# -----------------------------
echo "[+] Installing SSL scanner..."

if [ ! -d "$HOME/tools/testssl" ]; then
    git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl
fi

# -----------------------------
# WORDLISTS
# -----------------------------
echo "[+] Setting up wordlists..."

if [ ! -d "/usr/share/seclists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

# -----------------------------
# NUCLEI TEMPLATES
# -----------------------------
echo "[+] Updating Nuclei templates..."

nuclei -update-templates || echo "[!] nuclei templates update skipped"

# -----------------------------
# TOOL VERIFICATION
# -----------------------------
echo "[+] Verifying important tools..."

tools_check=(subfinder httpx nuclei naabu ffuf nmap katana)

for cmd in "${tools_check[@]}"; do
    if command -v $cmd &> /dev/null; then
        echo "[✔] $cmd installed"
    else
        echo "[✘] $cmd missing"
    fi
done

# -----------------------------
# FINAL MESSAGE
# -----------------------------
echo ""
echo "[🔥] ReconStorm Installation Completed Successfully!"
echo "[👉] Restart terminal OR run: source ~/.zshrc / ~/.bashrc"
