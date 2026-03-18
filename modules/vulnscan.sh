#!/bin/bash

domain=$1
base=$2

echo "[+] Running Vulnerability Scanning..."

nuclei -l $base/recon/live_hosts.txt \
 -severity critical,high,medium \
 -silent \
 -o $base/vuln/nuclei.txt

nikto -h http://$domain -o $base/vuln/nikto.txt

dalfox file $base/recon/urls.txt \
 --mass \
 -o $base/vuln/xss_scan.txt
