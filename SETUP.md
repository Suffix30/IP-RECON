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
