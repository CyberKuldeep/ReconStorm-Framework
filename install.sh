#!/bin/bash

echo "[+] Updating system..."
sudo apt update -y

echo "[+] Installing base dependencies..."

sudo apt install -y \
git curl wget jq whois dnsutils build-essential \
nmap masscan ffuf dirsearch nikto sqlmap \
python3 python3-pip python3-venv pipx \
golang-go libpcap-dev unzip snapd chromium \
amass whatweb wafw00f dnsrecon dnsenum \
feroxbuster gobuster seclists

# Fix PATH
export PATH=$PATH:$(go env GOPATH)/bin

echo "[+] Installing Go Recon Tools..."

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/gwen001/github-subdomains@latest

echo "[+] Installing Live Host + Crawlers..."

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

echo "[+] Installing Port Scanners..."

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
curl -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
cargo install rustscan

echo "[+] Installing Enumeration Tools..."

go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

echo "[+] Installing Vulnerability Scanners..."

go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/anew@latest

echo "[+] Installing Subdomain Takeover..."

go install github.com/PentestPad/subzy@latest

echo "[+] Installing Directory Bruteforce..."

# Already installed: ffuf, dirsearch, feroxbuster, gobuster

echo "[+] Installing JS Analysis Tools..."

pipx ensurepath

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

echo "[+] Installing Screenshot Tool..."

go install github.com/sensepost/gowitness@latest

echo "[+] Installing OSINT Tools..."

sudo apt install -y theharvester recon-ng

echo "[+] Installing Web Tech + WAF Detection..."

# Already installed: whatweb, wafw00f

echo "[+] Installing SSL Scanner..."

if [ ! -d "$HOME/tools/testssl" ]; then
    git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl
fi

echo "[+] Installing CMS Scanners..."

sudo apt install -y wpscan joomscan droopescan

echo "[+] Installing Exploitation Tools..."

sudo apt install -y metasploit-framework

echo "[+] Installing Nuclei Templates..."

nuclei -update-templates

echo "[+] Installing Wordlists..."

if [ ! -d "/usr/share/seclists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

echo "[+] ReconStorm ULTIMATE installation completed 🔥"
