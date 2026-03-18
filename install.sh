#!/bin/bash

set -e

echo "[+] Starting ReconStorm Installation 🔥"

# -----------------------------
# UPDATE SYSTEM & UPGRADE
# -----------------------------
echo "[+] Updating system..."
sudo apt update -y && suao apt upgrade -y

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

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/gwen001/github-subdomains@latest

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest

go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/anew@latest

go install github.com/PentestPad/subzy@latest
go install github.com/sensepost/gowitness@latest

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
# PYTHON TOOLS (PEP 668 SAFE)
# -----------------------------
echo "[+] Installing Python tools..."

pipx ensurepath --force

pipx install droopescan || true

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

nuclei -update-templates

# -----------------------------
# FINAL MESSAGE
# -----------------------------
echo ""
echo "[✔] ReconStorm Installation Completed Successfully 🚀"
echo "[✔] Restart your terminal or run: source ~/.bashrc"
