#!/bin/bash

domain=$1

if [ -z "$domain" ]; then
 echo "Usage: ./ReconStorm.sh target.com"
 exit
fi

source config/api_keys.conf

date=$(date +%F)
base_dir="output/${domain}-${date}"

mkdir -p "$base_dir"/{recon,scan,enum,vuln,exploit,intelligence,report}

echo "[+] Starting BugSploit Framework on $domain"

bash modules/recon.sh $domain $base_dir
bash modules/scanning.sh $domain $base_dir
bash modules/enumeration.sh $domain $base_dir
bash modules/vulnscan.sh $domain $base_dir
bash modules/exploitation.sh $domain $base_dir
bash modules/intelligence.sh $domain $base_dir
bash modules/reporting.sh $domain $base_dir

echo "[+] Scan Complete
