
# IP Recon Tool

## Overview

The **IP Recon Tool** is a versatile network reconnaissance utility that combines various tools and scanning techniques to analyze an IP address, port, or URL. Results are organized in a structured directory, making it easy to review the findings. This tool supports both **terminal-based** and **GUI-based** operations for enhanced usability.

---

## Features

- **Terminal Script**: Execute network scans directly from the command line with detailed output.
- **GUI Interface**: Provides a user-friendly interface for initiating scans with customizable inputs.
- **Comprehensive Scanning**:
  - Ping, traceroute, and port scanning.
  - SSL certificate checks and SMB enumeration.
  - Web reconnaissance with WhatWeb, Nikto, and Gobuster.
  - Exploitation preparation using Metasploit auxiliary scanners.
- **Result Organization**: All results are saved in a structured directory under `~/Documents/ip_recon_results`.

---

## Requirements

Before running the tool, ensure the following dependencies are installed:

### Required Tools

- **Command-line utilities**: `traceroute`, `nmap`, `whois`, `nslookup`, `netcat`, `curl`, `openssl`
- **Web analysis tools**: `sslscan`, `whatweb`, `nikto`, `gobuster`
- **SMB enumeration tool**: `enum4linux`
- **Exploitation framework**: `metasploit-framework`

### Install Dependencies

On Debian-based systems (e.g., Kali Linux):

```bash
sudo apt-get install traceroute nmap whois dnsutils netcat curl sslscan openssl whatweb nikto gobuster enum4linux metasploit-framework
```

For Python dependencies (GUI version):

```bash
pip install customtkinter
```

---

## Folder Structure

```
project_root/
├── ip_recon.sh         # Terminal-based network scanning script
├── ip_recon_gui.py         # GUI-based network scanning script
├── requirements.txt    # List of Python dependencies
└── README.md           # Documentation
```

---

## Usage

### Terminal Version

1. **Make the script executable:**
   ```bash
   chmod +x ip_recon.sh
   ```

2. **Run the script:**
   - Default values:
     ```bash
     sudo ./ip_recon.sh
     ```
   - Custom values:
     ```bash
     sudo ./ip_recon.sh <IP> <PORT> <URL> <WORDLIST_PATH> <METASPLOIT_OPTIONS> <NMAP_OPTIONS>
     ```

3. **Output**: Results are saved in the directory:
   ```
   ~/Documents/ip_recon_results/
   ```

### GUI Version

1. **Run the GUI script:**
   ```bash
   python3 ip_recon_gui.py
   ```

2. **Input details in the GUI**:
   - Enter IP address, port, URL, wordlist path, Metasploit options, and Nmap options.
   - Use the **Browse** button to select a wordlist file.
   - Click **Run Script** to start scanning.

3. **Stop the scan**:
   - Use the **Stop Script** button to terminate the running process.

---

## Output Example

Results are saved in `~/Documents/ip_recon_results/` with the following structure:

```
ip_recon_results/
├── ip_scan/
│   ├── ping_results.txt
│   ├── traceroute_results.txt
│   ├── nmap_results.txt
│   ├── whois_results.txt
│   ├── nslookup_results.txt
│   ├── nc_results.txt
│   ├── sslscan_results.txt
│   ├── openssl_results.txt
│   ├── enum4linux_results.txt
│   └── metasploit_results.txt
└── url_scan/
    ├── whatweb_results.txt
    ├── nikto_results.txt
    ├── gobuster_results.txt
    └── curl_results.txt
```

---

## Features in the GUI Version

### Real-Time Monitoring
- The GUI dynamically updates log outputs in a dedicated text box while scans are in progress.

### Error Handling
- Invalid inputs or missing tools are flagged with error messages.

### Customizable Scans
- Fields for:
  - IP address
  - Port
  - URL
  - Wordlist path
  - Metasploit options
  - Nmap options

### Process Management
- The GUI allows users to stop the scan process mid-execution using a **Stop Script** button.

---

## Contribution

Contributions and feedback are welcome. To suggest improvements or report issues, submit a pull request or open an issue in the repository.

