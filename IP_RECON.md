# Network Scanning Script

This script runs various network scanning tools against a specified IP, port, and URL. The results of each scan are saved in a `results` directory within the `Documents` folder on Kali Linux.

## Requirements

Install the following tools before running the script:

- traceroute
- nmap
- whois
- nslookup
- netcat
- curl
- sslscan
- openssl
- whatweb
- nikto
- gobuster
- enum4linux
- metasploit-framework

### Installing Requirements

On a Debian-based system, you can install the tools with the following command:

```bash
sudo apt-get install traceroute nmap whois dnsutils netcat curl sslscan openssl whatweb nikto gobuster enum4linux metasploit-framework
```

## Script

Save the following script as `ip_recon.sh`:

```bash
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
```

## Usage

1. **Make the script executable:**

    ```bash
    chmod +x ip_recon.sh
    ```

2. **Run the script with default values:**

    ```bash
    sudo ./ip_recon.sh
    ```

3. **Run the script with custom values:**

    ```bash
    sudo ./ip_recon.sh <IP> <PORT> <URL> <WORDLIST_PATH> <METASPLOIT_OPTIONS> <NMAP_OPTIONS>
    ```

## Folder Structure

```
project_root/
├── ip_recon.sh
└── requirements.txt
```

## GUI Script

You can also use a GUI tool to run this script. Save the following script as `ip_recon.py`:

```python
import os
import subprocess
import threading
import customtkinter as ctk

running_process = None

def run_script():
    global running_process

    ip = ip_entry.get().strip()
    port = port_entry.get().strip()
    url = url_entry.get().strip()
    wordlist = wordlist_entry.get().strip()
    metasploit_options = metasploit_entry.get().strip()
    nmap_options = nmap_entry.get().strip()

    if not ip:
        ip = "127.0.0.1"  # Default IP
    if not port:
        port = "80"  # Default Port
    if not url:
        url = "https://example.com"  # Default URL
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # Default Wordlist
    if not metasploit_options:
        metasploit_options = "use auxiliary/scanner/ftp/ftp_version; set RHOSTS $IP; run;"  # Default Metasploit Options
    if not nmap_options:
        nmap_options = ""  # Default Nmap Options

    script_content = f"""
#!/bin/bash

IP="{ip}"
PORT="{port}"
URL="{url}"
BASE_DIR="/home/kali/Documents"
RESULTS_DIR="$BASE_DIR/ip_recon_results"
IP_SCAN_DIR="$RESULTS_DIR/ip_scan"
URL_SCAN_DIR="$RESULTS_DIR/url_scan"
WORDLIST="{wordlist}"
METASPLOIT_OPTIONS="{metasploit_options}"
NMAP_OPTIONS="{nmap_options}"

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
"""

    script_path = "/home/kali/Documents/ip_recon.sh"
    with open(script_path, 'w') as file:
        file.write(script_content)

    subprocess.run(["chmod", "+x", script_path])
    
    running_process = subprocess.Popen(["sudo", script_path])

def stop_script():
    global running_process
    if running_process:
        running_process.terminate()
        running_process = None
        print("Script execution stopped.")

app = ctk.CTk()

app.title("IP Recon")
app.geometry("400x500")

ctk.CTkLabel(app, text="IP Recon Tool").pack(pady=10)

ctk.CTkLabel(app, text="IP Address").pack()
ip_entry = ctk.CTkEntry(app)
ip_entry.pack()

ctk.CTkLabel(app, text="Port").pack()
port_entry = ctk.CTkEntry(app)
port_entry.pack()

ctk.CTkLabel(app, text="URL").pack()
url_entry = ctk.CTkEntry(app)
url_entry.pack()

ctk.CTkLabel(app, text="Word List Path").pack()
wordlist_entry = ctk.CTkEntry(app)
wordlist_entry.pack()

ctk.CTkLabel(app, text="Metasploit Options").pack()
metasploit_entry = ctk.CTkEntry(app)
metasploit_entry.pack()

ctk.CTkLabel(app, text="Nmap Options").pack()
nmap_entry = ctk.CTkEntry(app)
nmap_entry.pack()

ctk.CTkButton(app, text="Run Script", command=lambda: threading.Thread(target=run_script).start()).pack(pady=10)
ctk.CTkButton(app, text="Stop Script", command=stop_script).pack(pady=10)

app.mainloop()
```

## Usage

1. **Run the GUI script:**

    ```bash
    python3 ip_recon.py
    ```

2. **Input the necessary details in the GUI and run the script.**

## Folder Structure

```
project_root/
├── ip_recon.sh
├── ip_recon.py
└── requirements.txt
```
