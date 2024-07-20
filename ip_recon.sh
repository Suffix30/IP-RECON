#!/bin/bash

IP="${1:-127.0.0.1}"  # Default IP
PORT="${2:-80}"  # Default Port
URL="${3:-https://example.com}"  # Default URL
BASE_DIR="$HOME/Documents"
RESULTS_DIR="$BASE_DIR/ip_recon_results"
IP_SCAN_DIR="$RESULTS_DIR/ip_scan"
URL_SCAN_DIR="$RESULTS_DIR/url_scan"
WORDLIST="${4:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"  # Default Wordlist
METASPLOIT_OPTIONS="${5:-use auxiliary/scanner/ftp/ftp_version; set RHOSTS $IP; run;}"  # Default Metasploit Options
NMAP_OPTIONS="${6:-}"  # Default Nmap Options

echo "BASE_DIR: $BASE_DIR"
echo "RESULTS_DIR: $RESULTS_DIR"
echo "IP_SCAN_DIR: $IP_SCAN_DIR"
echo "URL_SCAN_DIR: $URL_SCAN_DIR"

mkdir -p "$IP_SCAN_DIR"
mkdir -p "$URL_SCAN_DIR"

if [ -d "$IP_SCAN_DIR" ] && [ -d "$URL_SCAN_DIR" ]; then
  echo "㉿ Directories $IP_SCAN_DIR and $URL_SCAN_DIR created successfully.㉿"
else
  echo "㉿ Failed to create directories $IP_SCAN_DIR and $URL_SCAN_DIR.㉿"
  exit 1
fi

if [ -n "$IP" ] && [ -n "$PORT" ]; then
  echo "[*] ㉿ Pinging $IP..."
  ping -c 10 $IP > "$IP_SCAN_DIR/ping_results.txt"

  echo "[*] ㉿ Running traceroute to $IP..."
  sudo traceroute -T $IP > "$IP_SCAN_DIR/traceroute_results.txt" 2>&1

  echo "[*] ㉿ Scanning $IP with nmap..."
  sudo nmap -A -T4 -p $PORT $NMAP_OPTIONS $IP > "$IP_SCAN_DIR/nmap_results.txt"

  echo "[*] ㉿ Running whois on $IP..."
  whois $IP > "$IP_SCAN_DIR/whois_results.txt"

  echo "[*] ㉿ Running nslookup on $IP..."
  nslookup $IP > "$IP_SCAN_DIR/nslookup_results.txt"

  echo "[*] ㉿ Checking port $PORT with netcat..."
  echo -e "GET / HTTP/1.1\\nHost: $IP\\n\\n" | nc -v $IP $PORT > "$IP_SCAN_DIR/nc_results.txt" 2>&1

  echo "[*] ㉿ Running SSL scan on $IP:$PORT..."
  sslscan --no-failed $IP:$PORT > "$IP_SCAN_DIR/sslscan_results.txt"

  echo "[*] ㉿ Running OpenSSL s_client to check SSL certificates..."
  echo | openssl s_client -connect $IP:$PORT > "$IP_SCAN_DIR/openssl_results.txt" 2>&1

  echo "[*] ㉿ Running Enum4Linux for SMB enumeration on $IP..."
  if command -v enum4linux &> /dev/null
  then
      enum4linux -a $IP > "$IP_SCAN_DIR/enum4linux_results.txt"
  else
      echo "Enum4Linux is not installed. Skipping Enum4Linux scan."
  fi

  echo "[*] ㉿ Running Metasploit auxiliary scanners on $IP..."
  msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS $IP; run; $METASPLOIT_OPTIONS exit" > "$IP_SCAN_DIR/metasploit_results.txt"
fi

if [ -n "$URL" ]; then
  echo "[*] ㉿ Running WhatWeb to identify technologies used on $URL..."
  whatweb --no-errors -a 3 $URL > "$URL_SCAN_DIR/whatweb_results.txt"

  echo "[*] ㉿ Running Nikto to check for web vulnerabilities on $URL..."
  nikto -h $URL > "$URL_SCAN_DIR/nikto_results.txt"

  echo "[*] ㉿ Running Gobuster to discover directories and files on $URL..."
  if command -v gobuster &> /dev/null
  then
      gobuster dir -u $URL -w $WORDLIST -k -o "$URL_SCAN_DIR/gobuster_results.txt"
  else
      echo "㉿㉿㉿ Gobuster is not installed. Skipping Gobuster scan.㉿㉿㉿"
  fi

  echo "[*] ㉿ Running curl to check HTTPS response for $URL..."
  curl -I -k -v $URL > "$URL_SCAN_DIR/curl_results.txt" 2>&1
fi

echo "[*] ㉿ Reconnaissance completed. Results saved in $RESULTS_DIR"
