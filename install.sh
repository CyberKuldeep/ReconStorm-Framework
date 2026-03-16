#!/bin/bash

echo "[+] Updating system..."

sudo apt update -y

echo "[+] Installing base dependencies..."

sudo apt install -y \
git curl wget jq whois dnsutils build-essential \
nmap masscan ffuf dirsearch nikto sqlmap \
python3 python3-pip golang-go

echo "[+] Installing Go based tools..."

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest

go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/anew@latest

echo "[+] Installing additional recon tools..."

go install github.com/projectdiscovery/uncover/cmd/uncover@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

echo "[+] Installing Subdomain Takeover tool..."

go install github.com/PentestPad/subzy@latest

echo "[+] Installing JS analysis tools..."

git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
pip3 install -r ~/tools/LinkFinder/requirements.txt

git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
pip3 install -r ~/tools/SecretFinder/requirements.txt

echo "[+] Installing screenshot tool..."

go install github.com/sensepost/gowitness@latest

echo "[+] Installing crawler tools..."

go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "[+] Installing vulnerability tools..."

go install github.com/hahwul/dalfox/v2@latest

echo "[+] Installing GitHub subdomain tool..."

go install github.com/gwen001/github-subdomains@latest

echo "[+] Installing OSINT tools..."

sudo apt install -y theharvester

echo "[+] Installing SSL scanner..."

git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl

echo "[+] Installing Rustscan..."

curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
cargo install rustscan

echo "[+] Installing Amass..."

sudo snap install amass

echo "[+] Updating Nuclei Templates..."

nuclei -update-templates

echo "[+] ReconStorm installation completed successfully!"
