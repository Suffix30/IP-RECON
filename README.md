# IP Recon Tool

## Overview

The **IP Recon Tool** is a versatile network reconnaissance utility that combines various tools and scanning techniques to analyze an IP address, port, or URL. Results are organized in a structured directory, making it easy to review the findings. This tool supports both **terminal-based** and **GUI-based** operations for enhanced usability.

## Quick Start

### CLI
```bash
sudo ./ip_recon.sh 192.168.1.1 80 https://example.com
```

### GUI
```bash
python3 ip_recon_gui.py
```

## Features

- **Terminal Script**: Execute network scans directly from the command line with detailed output.
- **GUI Interface**: Provides a user-friendly interface for initiating scans with customizable inputs.
- **Comprehensive Scanning**:
  - **Ping**: Basic connectivity test.
  - **Traceroute**: Network path analysis.
  - **Nmap**: Port and service scanning (aggressive or stealth mode).
  - **Whois**: Domain ownership lookup.
  - **Nslookup**: DNS resolution.
  - **Netcat**: Port connectivity test.
  - **SSLScan/OpenSSL**: SSL/TLS certificate and vulnerability checks.
  - **WhatWeb**: Web technology identification.
  - **Nikto**: Web vulnerability scanner.
  - **Gobuster**: Directory brute-forcing.
  - **Enum4linux**: SMB enumeration.
  - **Metasploit**: Auxiliary scanning and exploitation prep.
- **Result Organization**: All results are saved in `~/Documents/ip_recon_results`.

## Requirements

### Python Dependencies
Install via pip:
```bash
pip install -r requirements.txt
```

### System Tools
Install on Debian-based systems (e.g., Kali Linux):
```bash
sudo apt-get install traceroute nmap whois dnsutils netcat curl sslscan openssl whatweb nikto gobuster enum4linux metasploit-framework
```

## Folder Structure
```
project_root/
├── ip_recon.sh         # Terminal-based network scanning script
├── ip_recon_gui.py     # GUI-based network scanning script
├── requirements.txt    # Python dependencies
├── README.md           # Documentation
└── SETUP.md            # Installation guide
```

## Usage

### Terminal Version

Make the script executable:
```bash
chmod +x ip_recon.sh
```

Run with custom values:
```bash
sudo ./ip_recon.sh <IP> <PORT> <URL> <WORDLIST_PATH> <METASPLOIT_OPTIONS> <NMAP_OPTIONS> <SCAN_MODE>
```

**Example:**
```bash
sudo ./ip_recon.sh 192.168.1.1 443 https://target.com /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt "use auxiliary/scanner/ftp/ftp_version; set RHOSTS 192.168.1.1; run;" "-Pn" stealth
```

**Optional flags:**
- `--no-nmap`: Skip Nmap scan.
- `--only-web`: Scan only the URL.

**Output**: Results saved in `~/Documents/ip_recon_results/`.

### GUI Version

Run the script:
```bash
python3 ip_recon_gui.py
```

**Input details:**
- **IP Address**: e.g., `192.168.1.1`
- **Port**: e.g., `443`
- **URL**: e.g., `https://target.com`
- **Wordlist Path**: e.g., `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- **Metasploit Options**: e.g., `use auxiliary/scanner/ftp/ftp_version; set RHOSTS 192.168.1.1; run;`
- **Nmap Options**: e.g., `-Pn`
- **Scan Mode**: `aggressive` or `stealth`

Click **"Run Script"** to start, **"Stop Script"** to terminate.

## Contribution

Contributions and feedback are welcome. Submit a pull request or open an issue in the repository.

---

## SETUP.md

### IP Recon Tool Setup

### Requirements

Install the following tools before running the script:

- `traceroute`
- `nmap`
- `whois`
- `nslookup` (dnsutils)
- `netcat`
- `curl`
- `sslscan`
- `openssl`
- `whatweb`
- `nikto`
- `gobuster`
- `enum4linux`
- `metasploit-framework`

### Installing System Tools

#### On Debian-based systems (e.g., Kali Linux):
```bash
sudo apt-get install traceroute nmap whois dnsutils netcat curl sslscan openssl whatweb nikto gobuster enum4linux metasploit-framework
```

#### On Arch-based systems:
```bash
sudo pacman -S traceroute nmap whois bind-tools netcat curl sslscan openssl whatweb nikto gobuster enum4linux metasploit
```

### Installing Python Dependencies
```bash
pip install -r requirements.txt
```

### Troubleshooting
- **Permission Denied**: Run with `sudo` or check permissions (`chmod +x ip_recon.sh`).
- **Tool Not Found**: Install missing tools with `sudo apt-get install <tool>`.
- **GUI Fails to Launch**: Ensure `customtkinter` is installed and Python 3 is used.
