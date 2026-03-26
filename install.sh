#!/bin/bash

set -euo pipefail

echo "[+] Starting ReconStorm Installation 🔥"

# Function to add a path to shell configuration files persistently
add_path_persistent() {
    local path_to_add="$1"
    local shell_config_files=("$HOME/.bashrc" "$HOME/.zshrc")

    for file in "${shell_config_files[@]}"; do
        if [ -f "$file" ]; then
            if ! grep -q "$path_to_add" "$file" 2>/dev/null; then
                echo "export PATH=\$PATH:$path_to_add" >> "$file"
                echo "[+] Added $path_to_add to $file"
            else
                echo "[✔] PATH $path_to_add already exists in $file"
            fi
        fi
    done
    # Apply immediately for the current session
    export PATH=$PATH:$path_to_add
}

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
# INSTALL GO (Latest Stable Version)
# -----------------------------
echo "[+] Installing/Updating Go to the latest stable version..."
GO_LATEST_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1)
GO_TAR_FILE="${GO_LATEST_VERSION}.linux-amd64.tar.gz"
GO_DOWNLOAD_URL="https://go.dev/dl/${GO_TAR_FILE}"

if ! command -v go &> /dev/null || [[ "$(go version | awk '{print $3}')" != "${GO_LATEST_VERSION}" ]]; then
    echo "[+] Downloading ${GO_LATEST_VERSION}..."
    wget -q "$GO_DOWNLOAD_URL"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TAR_FILE"
    rm "$GO_TAR_FILE"
    add_path_persistent "/usr/local/go/bin"
else
    echo "[✔] Go ${GO_LATEST_VERSION} is already installed."
fi

# Ensure GOPATH is set and added to PATH persistently
export GOPATH="$HOME/go"
mkdir -p "$GOPATH/bin"
add_path_persistent "$GOPATH/bin"

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
    if ! go install "$tool@latest"; then
        echo "[!] Failed to install $tool. Please check for errors."
    else
        echo "[✔] Successfully installed $tool"
    fi
done

# -----------------------------
# RUSTSCAN
# -----------------------------
echo "[+] Installing Rustscan..."

if ! command -v rustscan &> /dev/null; then
    echo "[+] Installing Rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # Source cargo env for current session
    source "$HOME/.cargo/env"
    # Add cargo bin to PATH persistently
    add_path_persistent "$HOME/.cargo/bin"
    echo "[+] Installing Rustscan via cargo..."
    cargo install rustscan
else
    echo "[✔] Rustscan is already installed."
fi

# -----------------------------
# PYTHON TOOLS
# -----------------------------
echo "[+] Installing Python tools..."

pipx ensurepath --force
if ! pipx install droopescan; then
    echo "[!] Failed to install droopescan. Skipping."
else
    echo "[✔] Successfully installed droopescan"
fi

# -----------------------------
# JS ANALYSIS TOOLS
# -----------------------------
echo "[+] Installing JS analysis tools..."

mkdir -p ~/tools

# LinkFinder
if [ ! -d "$HOME/tools/LinkFinder" ]; then
    echo "[+] Cloning LinkFinder..."
    git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
    python3 -m venv ~/tools/linkfinder-venv
    source ~/tools/linkfinder-venv/bin/activate
    pip install -r ~/tools/LinkFinder/requirements.txt
    deactivate
    echo "[✔] LinkFinder installed."
else
    echo "[✔] LinkFinder already exists."
fi

# SecretFinder
if [ ! -d "$HOME/tools/SecretFinder" ]; then
    echo "[+] Cloning SecretFinder..."
    git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
    python3 -m venv ~/tools/secretfinder-venv
    source ~/tools/secretfinder-venv/bin/activate
    pip install -r ~/tools/SecretFinder/requirements.txt
    deactivate
    echo "[✔] SecretFinder installed."
else
    echo "[✔] SecretFinder already exists."
fi

# -----------------------------
# SSL SCANNER
# -----------------------------
echo "[+] Installing SSL scanner..."

if [ ! -d "$HOME/tools/testssl" ]; then
    echo "[+] Cloning testssl.sh..."
    git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl
    echo "[✔] testssl.sh installed."
else
    echo "[✔] testssl.sh already exists."
fi

# -----------------------------
# WORDLISTS
# -----------------------------
echo "[+] Setting up wordlists..."

if [ ! -d "/usr/share/seclists" ]; then
    echo "[+] Cloning SecLists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    echo "[✔] SecLists installed."
else
    echo "[✔] SecLists already exists."
fi

# -----------------------------
# NUCLEI TEMPLATES
# -----------------------------
echo "[+] Updating Nuclei templates..."

if ! nuclei -update-templates; then
    echo "[!] Failed to update Nuclei templates. Skipping."
else
    echo "[✔] Nuclei templates updated."
fi

# -----------------------------
# TOOL VERIFICATION
# -----------------------------
echo "[+] Verifying important tools..."

tools_check=(subfinder httpx nuclei naabu ffuf nmap katana rustscan droopescan LinkFinder SecretFinder testssl.sh)

for cmd in "${tools_check[@]}"; do
    if command -v $cmd &> /dev/null || ([ "$cmd" == "LinkFinder" ] && [ -d "$HOME/tools/LinkFinder" ]) || ([ "$cmd" == "SecretFinder" ] && [ -d "$HOME/tools/SecretFinder" ]) || ([ "$cmd" == "testssl.sh" ] && [ -d "$HOME/tools/testssl" ]); then
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
echo "[👉] Please restart your terminal or run 'source ~/.bashrc' or 'source ~/.zshrc' to apply PATH changes."
