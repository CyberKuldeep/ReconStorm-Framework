#!/bin/bash

domain=$1
base=$2

echo "[+] Running Enumeration..."

ffuf -w /usr/share/wordlists/dirb/common.txt \
-u http://$domain/FUZZ \
-mc 200,204,301,302 \
-t 100 \
-o $base/enum/ffuf.txt

dirsearch -u http://$domain \
-e php,html,js \
-o $base/enum/dirsearch.txt
