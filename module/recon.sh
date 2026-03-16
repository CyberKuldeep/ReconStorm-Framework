#!/bin/bash

domain=$1
base=$2

echo "[+] Running Recon..."

subfinder -d $domain -silent > $base/recon/subfinder.txt &
assetfinder --subs-only $domain > $base/recon/assetfinder.txt &
amass enum -passive -d $domain > $base/recon/amass.txt &

wait

cat $base/recon/*.txt | sort -u > $base/recon/subdomains.txt

httpx -l $base/recon/subdomains.txt \
 -threads 200 \
 -status-code \
 -title \
 -tech-detect \
 -silent > $base/recon/live_hosts.txt

gau $domain > $base/recon/urls.txt

katana -list $base/recon/live_hosts.txt -silent > $base/recon/crawled_urls.txt
