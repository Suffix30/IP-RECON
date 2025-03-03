#!/bin/bash

IP="${1:-127.0.0.1}"
PORT="${2:-80}"
URL="${3:-https://example.com}"
BASE_DIR="$HOME/Documents"
RESULTS_DIR="$BASE_DIR/ip_recon_results"
IP_SCAN_DIR="$RESULTS_DIR/ip_scan"
URL_SCAN_DIR="$RESULTS_DIR/url_scan"
WORDLIST="${4:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"
METASPLOIT_OPTIONS="${5:-use auxiliary/scanner/ftp/ftp_version; set RHOSTS $IP; run;}"
NMAP_OPTIONS="${6:-}"
SCAN_MODE="${7:-aggressive}"

NMAP_SKIP=0
ONLY_WEB=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-nmap) NMAP_SKIP=1; shift ;;
        --only-web) ONLY_WEB=1; shift ;;
        *) shift ;;
    esac
done

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "\e[31m$(date +'%Y-%m-%d %H:%M:%S') - Error: $1 is not installed. Please install it.\e[0m" | tee -a "$RESULTS_DIR/recon.log"
        exit 1
    fi
}

for tool in nmap traceroute whois nc sslscan openssl whatweb nikto gobuster metasploit-framework; do
    check_tool "$tool"
done

if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "$IP" =~ / ]]; then
    echo -e "\e[31m$(date +'%Y-%m-%d %H:%M:%S') - Error: Invalid IP format: $IP\e[0m" | tee -a "$RESULTS_DIR/recon.log"
    exit 1
fi

if [ -d "$RESULTS_DIR" ]; then
    mv "$RESULTS_DIR" "$RESULTS_DIR_$(date +'%Y%m%d_%H%M%S')"
    echo -e "\e[32m$(date +'%Y-%m-%d %H:%M:%S') - Previous results archived.\e[0m" | tee -a "$RESULTS_DIR/recon.log"
fi

mkdir -p "$IP_SCAN_DIR" "$URL_SCAN_DIR"

log_action() {
    echo -e "\e[32m$(date +'%Y-%m-%d %H:%M:%S') - $1\e[0m" | tee -a "$RESULTS_DIR/recon.log"
}

perform_ip_scan() {
    log_action "Starting IP reconnaissance on $1"
    (ping -c 10 "$1" > "$IP_SCAN_DIR/ping_results_$1.txt" 2>&1) &
    (whois "$1" > "$IP_SCAN_DIR/whois_results_$1.txt" 2>&1) &
    wait
    log_action "Running traceroute to $1..."
    sudo traceroute -T "$1" > "$IP_SCAN_DIR/traceroute_results_$1.txt" 2>&1
    if [ "$NMAP_SKIP" -eq 0 ]; then
        log_action "Scanning $1 with nmap ($SCAN_MODE mode)..."
        if [ "$SCAN_MODE" == "stealth" ]; then
            sudo nmap -sS -T2 -p "$PORT" "$NMAP_OPTIONS" "$1" > "$IP_SCAN_DIR/nmap_results_$1.txt" 2>&1
        else
            sudo nmap -A -T4 -p "$PORT" "$NMAP_OPTIONS" "$1" > "$IP_SCAN_DIR/nmap_results_$1.txt" 2>&1
        fi
    fi
    log_action "Running nslookup on $1..."
    nslookup "$1" > "$IP_SCAN_DIR/nslookup_results_$1.txt" 2>&1
    log_action "Checking port $PORT with netcat on $1..."
    echo -e "GET / HTTP/1.1\nHost: $1\n\n" | nc -v "$1" "$PORT" > "$IP_SCAN_DIR/nc_results_$1.txt" 2>&1
    log_action "Running SSL scan on $1:$PORT..."
    sslscan --no-failed "$1:$PORT" > "$IP_SCAN_DIR/sslscan_results_$1.txt" 2>&1
    log_action "Checking SSL certificates with OpenSSL on $1:$PORT..."
    echo | openssl s_client -connect "$1:$PORT" > "$IP_SCAN_DIR/openssl_results_$1.txt" 2>&1
    log_action "Running Enum4linux for SMB enumeration on $1..."
    if command -v enum4linux &> /dev/null; then
        enum4linux -a "$1" > "$IP_SCAN_DIR/enum4linux_results_$1.txt" 2>&1
    else
        log_action "Enum4linux not installed. Skipping SMB enumeration on $1."
    fi
    log_action "Running Metasploit auxiliary scanners on $1..."
    msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS $1; run; $METASPLOIT_OPTIONS exit" > "$IP_SCAN_DIR/metasploit_results_$1.txt" 2>&1
}

perform_url_scan() {
    log_action "Starting URL reconnaissance on $1"
    log_action "Running WhatWeb on $1..."
    whatweb --no-errors -a 3 "$1" > "$URL_SCAN_DIR/whatweb_results_$1.txt" 2>&1
    log_action "Running Nikto on $1..."
    nikto -h "$1" > "$URL_SCAN_DIR/nikto_results_$1.txt" 2>&1
    log_action "Running Gobuster on $1..."
    if command -v gobuster &> /dev/null; then
        gobuster dir -u "$1" -w "$WORDLIST" -k -o "$URL_SCAN_DIR/gobuster_results_$1.txt" 2>&1
    else
        log_action "Gobuster not installed. Skipping directory brute-forcing on $1."
    fi
    log_action "Fetching HTTPS response headers for $1 with curl..."
    curl -I -k -v "$1" > "$URL_SCAN_DIR/curl_results_$1.txt" 2>&1
}

if [[ -f "$IP" ]]; then
    while read -r target_ip; do
        perform_ip_scan "$target_ip"
    done < "$IP"
elif [[ "$IP" =~ "/" ]]; then
    nmap -sL "$IP" | awk '/Nmap scan report/{print $NF}' | while read -r target_ip; do
        perform_ip_scan "$target_ip"
    done
else
    if [ "$ONLY_WEB" -eq 0 ]; then
        perform_ip_scan "$IP"
    fi
fi

if [ -n "$URL" ] && [ "$ONLY_WEB" -eq 1 ] || [ "$ONLY_WEB" -eq 0 ]; then
    perform_url_scan "$URL"
fi

log_action "Reconnaissance completed. Results saved in $RESULTS_DIR."
