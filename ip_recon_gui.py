import os
import subprocess
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

running_process = None

def validate_inputs(ip, port, url, wordlist):
    if not ip or not port or not url or not wordlist:
        messagebox.showerror("Error", "All fields must be filled.")
        return False
    if not port.isdigit():
        messagebox.showerror("Error", "Port must be a number.")
        return False
    if not os.path.isfile(wordlist):
        messagebox.showerror("Error", "Invalid wordlist path.")
        return False
    return True

def browse_wordlist():
    wordlist_path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text Files", "*.txt")])
    if wordlist_path:
        wordlist_entry.delete(0, "end")
        wordlist_entry.insert(0, wordlist_path)

def run_script():
    global running_process

    ip = ip_entry.get().strip()
    port = port_entry.get().strip()
    url = url_entry.get().strip()
    wordlist = wordlist_entry.get().strip()
    metasploit_options = metasploit_entry.get().strip()
    nmap_options = nmap_entry.get().strip()

    if not validate_inputs(ip, port, url, wordlist):
        return

    script_content = f"""
#!/bin/bash
IP="{ip}"
PORT="{port}"
URL="{url}"
BASE_DIR="$HOME/Documents"
RESULTS_DIR="$BASE_DIR/ip_recon_results"
IP_SCAN_DIR="$RESULTS_DIR/ip_scan"
URL_SCAN_DIR="$RESULTS_DIR/url_scan"
WORDLIST="{wordlist}"
METASPLOIT_OPTIONS="{metasploit_options or 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS $IP; run;'}"
NMAP_OPTIONS="{nmap_options or ''}"

mkdir -p "$IP_SCAN_DIR"
mkdir -p "$URL_SCAN_DIR"

echo "Starting IP Recon..."
ping -c 10 $IP > "$IP_SCAN_DIR/ping_results.txt"
sudo traceroute -T $IP > "$IP_SCAN_DIR/traceroute_results.txt" 2>&1
sudo nmap -A -T4 -p $PORT $NMAP_OPTIONS $IP > "$IP_SCAN_DIR/nmap_results.txt"
whois $IP > "$IP_SCAN_DIR/whois_results.txt"
nslookup $IP > "$IP_SCAN_DIR/nslookup_results.txt"
echo -e "GET / HTTP/1.1\\nHost: $IP\\n\\n" | nc -v $IP $PORT > "$IP_SCAN_DIR/nc_results.txt" 2>&1
sslscan --no-failed $IP:$PORT > "$IP_SCAN_DIR/sslscan_results.txt"
echo | openssl s_client -connect $IP:$PORT > "$IP_SCAN_DIR/openssl_results.txt" 2>&1
whatweb --no-errors -a 3 $URL > "$URL_SCAN_DIR/whatweb_results.txt"
nikto -h $URL > "$URL_SCAN_DIR/nikto_results.txt"
if command -v gobuster &> /dev/null; then
    gobuster dir -u $URL -w $WORDLIST -k -o "$URL_SCAN_DIR/gobuster_results.txt"
else
    echo "Gobuster is not installed. Skipping."
fi
echo "Recon completed. Results saved in $RESULTS_DIR"
"""
    script_path = os.path.expanduser("~/Documents/ip_recon.sh")
    with open(script_path, 'w') as file:
        file.write(script_content)

    os.chmod(script_path, 0o755)

    try:
        running_process = subprocess.Popen(["sudo", script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        threading.Thread(target=log_output, args=(running_process.stdout,)).start()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to execute script: {e}")

def stop_script():
    global running_process
    if running_process:
        running_process.terminate()
        running_process = None
        messagebox.showinfo("Info", "Script execution stopped.")

def log_output(pipe):
    for line in iter(pipe.readline, ''):
        log_text.insert("end", line)
        log_text.see("end")
    pipe.close()

app = ctk.CTk()
app.title("IP Recon")
app.geometry("500x600")

ctk.CTkLabel(app, text="IP Recon Tool", font=("Helvetica", 16)).pack(pady=10)

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
ctk.CTkButton(app, text="Browse", command=browse_wordlist).pack(pady=5)

ctk.CTkLabel(app, text="Metasploit Options").pack()
metasploit_entry = ctk.CTkEntry(app)
metasploit_entry.pack()

ctk.CTkLabel(app, text="Nmap Options").pack()
nmap_entry = ctk.CTkEntry(app)
nmap_entry.pack()

ctk.CTkButton(app, text="Run Script", command=lambda: threading.Thread(target=run_script).start()).pack(pady=10)
ctk.CTkButton(app, text="Stop Script", command=stop_script).pack(pady=10)

log_text = ctk.CTkTextbox(app, height=200, width=450)
log_text.pack(pady=10)

app.mainloop()
