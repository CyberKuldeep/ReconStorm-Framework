#!/bin/bash

domain=$1
base=$2

echo "[+] Gathering Intelligence..."

curl -s "https://crt.sh/?q=%25.$domain&output=json" > $base/intelligence/crtsh.json

curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" > $base/intelligence/hostsearch.txt

whois $domain > $base/intelligence/whois.txt
