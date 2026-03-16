#!/bin/bash

domain=$1
base=$2

echo "[+] Generating Report..."

echo "BugSploit Recon Report for $domain" > $base/report/summary.txt

echo "Subdomains Found:" >> $base/report/summary.txt
wc -l $base/recon/subdomains.txt >> $base/report/summary.txt

echo "Live Hosts:" >> $base/report/summary.txt
wc -l $base/recon/live_hosts.txt >> $base/report/summary.txt

echo "Nuclei Findings:" >> $base/report/summary.txt
grep -Ei "critical|high" $base/vuln/nuclei.txt >> $base/report/summary.txt
