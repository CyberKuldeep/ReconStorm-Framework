# ⚡ ReconStorm Framework

<p align="center">
  <b>Automated Bug Bounty Recon & VAPT Framework</b><br>
  <i>Built for Security Researchers, Pentesters & Bug Bounty Hunters</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bash-Automation-green">
  <img src="https://img.shields.io/badge/Security-VAPT-red">
  <img src="https://img.shields.io/badge/Status-Active-blue">
  <img src="https://img.shields.io/badge/BugBounty-Ready-orange">
</p>

---

## 🔥 Why ReconStorm?

Most tools solve only a **single part** of the bug bounty process.

👉 ReconStorm automates the **complete attack surface discovery pipeline**:

Recon → Scan → Enumeration → Scan Vulnerabilities → Find avaliable Exploits.

---

💀 No manual chaining  
⚡ Faster workflow  
🎯 Ready-to-hunt output  

---

## 🧠 Key Features

- 🧬 Smart Target Detection (Domain / IP)
- 🔍 Subdomain Enumeration
- 🌐 Live Host Detection
- 🕷 Endpoint Discovery
- 🎯 Parameter Extraction
- ⚡ Port Scanning (Naabu + Masscan + Nmap)
- 📂 Directory Bruteforce (FFUF + Dirsearch)
- 🔎 Vulnerability Scanning (Nuclei, Nikto, Dalfox)
- 💀 Exploitation Support (SQLMap, Searchsploit)
- 📸 Screenshot Capture (Gowitness)
- 📊 Clean Structured Output

---

## ⚙️ Architecture
```bash
modules/
├── recon.sh
├── scanning.sh
├── enumeration.sh
├── vulnscan.sh
└── exploitation.sh
```

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/ReconStorm-Framework.git
cd ReconStorm-Framework
chmod +x install.sh
./install.sh

```
## ▶️ Usage
🔹 Scan Domain
```bash
./ReconStorm.sh example.com
```
🔹 Scan IP
```bash
./ReconStorm.sh 192.168.1.1
```
📁 Output Structure
```bash
output/target-date/
├── recon/        # Subdomains, URLs, live hosts
├── scan/         # Ports, services
├── enum/         # Endpoints, parameters
├── vuln/         # Vulnerability findings
├── exploit/      # Exploits if Avalivable
└── logs/         # Logs
```
---

## 🛠 Tools Used
🔍 Recon

subfinder,
amass,
assetfinder, 
gau,
katana,
httpx  

⚡ Scanning

naabu,
masscan,
nmap

🕷 Enumeration

ffuf,
dirsearch,
gf,
dnsx,

🔎 Vulnerability

nuclei,
nikto,
dalfox,

💀 Exploitation

sqlmap,
searchsploit,
subzy,

📸 Demo
screenshots/very soon.png

## 🎯 Example Workflow
Input → example.com
```bash
↓ Recon
subdomains.txt → 100+ domains

↓ Scan
open ports → 80,443

↓ Enum
/admin, /api, /login

↓ Vuln
XSS, CVEs detected

↓ Exploit
SQLi confirmed
```
---
## ⚡ Performance

 - Parallel Execution

 - Fast Scanning

 - Reduced False Positives

 - Automation Friendly

## 🧠 Use Cases

- Bug Bounty Hunting

- VAPT Testing

- Red Team Recon

- Attack Surface Mapping

## ⚠️ Disclaimer

This tool is for educational and authorized security testing only.

You are responsible for your actions.

## 🚀 Future Updates

- 🤖 AI-based scanning

- 📊 HTML reporting dashboard

- ☁️ Cloud scanning

- ⚡ Multi-target scanning

## ⭐ Support

If you like this project:

- ⭐ Star the repo

- 🍴 Fork it

- 🔥 Share it

## 👨‍💻 Author

Kuldeep
Cybersecurity Enthusiast.
