#!/bin/bash

domain=$1
base=$2

echo "[+] Running Network Scanning..."

naabu -host $domain -top-ports 1000 -silent -o $base/scan/naabu.txt

nmap -sV -T4 -p- $domain -oN $base/scan/nmap.txt

masscan -p1-65535 $domain --rate 50000 -oG $base/scan/masscan.txt
