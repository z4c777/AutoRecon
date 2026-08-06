# AutoRecon

Automated enumeration for penetration testing. Point it at a target and it handles the rest — port discovery, service detection, targeted NSE scripts, and a clean summary report.

Made for HackTheBox CTFs.

Disclaimer: This tool was generated with AI.

---

## Installation

```bash
sudo apt install nmap
git clone https://github.com/z4c777/AutoRecon && cd AutoRecon
pip install python-nmap
```

# Run
```
python3 autorecon.py -t 10.129.98.84
```
Within 30 seconds you will see all open ports on the machine in your terminal output.  
Within 1 minute you will see versions for each open port.  
Complete scan with DNS/UDP/NSE scripts takes 8-10 minutes so be patient.  

Output folder is created automatically:
```
autorecon_10.129.98.84_20260805_224943/
```

---

## Installation

```bash
sudo apt install nmap
git clone https://github.com/z4c777/AutoRecon && cd AutoRecon
pip install python-nmap
```

---

## Usage

```bash
python3 autorecon.py -t TARGET [options]
```

| Flag | Description |
|------|-------------|
| `-t` | Target IP, hostname, or CIDR (required) |
| `-d`, `--domain` | Domain name for DNS enumeration e.g. `inlanefreight.local` |
| `-o` | Custom output directory |
| `--sweep` | Ping sweep subnet first, scan each live host |
| `--skip-udp` | Skip UDP scan |
| `--vuln` | Run vulnerability scan — disabled by default |
| `--ports-only` | Port discovery only — no scripts |
| `--oA` | Save nmap output in all formats (.nmap .gnmap .xml) |

### Examples

```bash
# Single target
python3 autorecon.py -t 10.129.98.84

# With domain — enables DNS enumeration and zone transfer
python3 autorecon.py -t 10.129.98.84 --domain inlanefreight.local

# Hostname target — domain auto-derived
python3 autorecon.py -t inlanefreight.local

# Subnet — discover and scan all live hosts
python3 autorecon.py -t 10.129.1.0/24 --sweep

# Fast scan — skip UDP scan
python3 autorecon.py -t 10.129.98.84 --skip-udp

# Include vulnerability scan
python3 autorecon.py -t 10.129.98.84 --vuln

# Save nmap output in all formats
python3 autorecon.py -t 10.129.98.84 --oA

# Custom output directory
python3 autorecon.py -t 10.129.98.84 -o /home/user/htb/machinename
```

---

## How It Works

The scan runs in up to 6 phases:

```
Phase 0  DNS enumeration            Record lookup + zone transfer (opt-in via --domain)
Phase 1  Fast TCP port discovery    nmap -p- --min-rate 5000
Phase 2  Service detection          nmap -sCV on open ports only
Phase 3  UDP scan                   nmap -sU --top-ports 100
Phase 4  NSE script enumeration     All scripts in ONE nmap call (TCP + UDP)
Phase 5  Vulnerability scan         nmap --script 'vuln and safe' (opt-in via --vuln)
```

Phase 4 combines all scripts for all open ports into a single nmap command instead of running one command per port — cuts scan time from ~10 minutes to ~2-3 minutes on a typical machine.

---

## Output

Every scan creates a timestamped folder named after the target:

```
autorecon_10.129.98.84_20260805_224943/
├── 00_dns_enum.txt              DNS record enumeration (Phase 0)
├── 00_dns_axfr_10_129_98_84.txt Zone transfer output if successful
├── 00_summary_report.txt        All findings in one place
├── 01_open_ports.txt            Open TCP ports
├── 02_service_detection.txt     Version and banner info
├── 03_udp_scan.txt              UDP results
├── 04_tcp_scripts.txt           All TCP NSE script output
├── 04_udp_scripts.txt           All UDP NSE script output
└── 05_vuln_scan.txt             Vulnerability findings (--vuln only)
```

The summary report shows:

```
OPEN PORTS
------------------------------------------------------------
  PORT         STATE    SERVICE      VERSION
  21/tcp       open     ftp          vsftpd 3.0.3
  | ftp-anon: Anonymous FTP login allowed (FTP code 230)
  |_-rw-r--r-- 1 0 0 38 May 30 2022 flag.txt

  22/tcp       open     ssh          OpenSSH 8.2p1 Ubuntu
  445/tcp      open     smb          Samba 4.x

SCRIPT ENUMERATION
------------------------------------------------------------
  [!] Port 21 — FTP
      Anonymous FTP login allowed

VULNERABILITIES FOUND
------------------------------------------------------------
  [!] smb-vuln-ms17-010: VULNERABLE
```

---

## Service Coverage

Scripts are automatically selected based on the detected service — even on non-standard ports.
For example FTP running on port 2121 still gets FTP scripts.

Sample of NSE scripts used:
### Network

| Port | Service | Key Scripts |
|------|---------|-------------|
| 21 | FTP | ftp-anon, ftp-vsftpd-backdoor, ftp-proftpd-backdoor |
| 22 | SSH | ssh-auth-methods, ssh2-enum-algos, ssh-hostkey |
| 23 | Telnet | telnet-ntlm-info, banner |
| 53 | DNS | dns-zone-transfer, dns-brute, dns-srv-enum |
| 69 | TFTP (UDP) | tftp-enum |
| 79 | Finger | finger |
| 111 | RPC | rpcinfo, nfs-showmount |
| 123 | NTP (UDP) | ntp-info, ntp-monlist |
| 873 | rsync | rsync-list-modules |

### Web

| Port | Service | Key Scripts |
|------|---------|-------------|
| 80 | HTTP | http-enum, http-methods, http-git, http-shellshock, http-vuln-* |
| 443 | HTTPS | All HTTP scripts + ssl-cert, ssl-enum-ciphers, ssl-heartbleed |
| 8080 | HTTP-Alt | All HTTP scripts |
| 8443 | HTTPS-Alt | All HTTP scripts + ssl-cert |
| 8009 | AJP/Tomcat | ajp-headers, ajp-methods, ajp-auth |

### Windows / Active Directory

| Port | Service | Key Scripts |
|------|---------|-------------|
| 88 | Kerberos | krb5-enum-users |
| 135 | MSRPC | msrpc-enum |
| 139 | NetBIOS | smb-os-discovery, smb-enum-shares, nbstat |
| 389 | LDAP | ldap-rootdse, ldap-search |
| 445 | SMB | smb-enum-shares, smb-enum-users, smb-vuln-ms17-010, smb-vuln-ms08-067 |
| 636 | LDAPS | ldap-rootdse, ssl-cert |
| 3268 | Global Catalog | ldap-rootdse, ldap-search |
| 3389 | RDP | rdp-enum-encryption, rdp-ntlm-info, rdp-vuln-ms12-020 |
| 5985 | WinRM | http-auth-finder, http-ntlm-info |

---

### Post-Scan Tips
After scanning each service actionable next steps are printed automatically. Example for IMAP:

```
[TIP] IMAP found — if on a Linux host try Evolution mail client:
      sudo apt install evolution
      Launch Evolution → New Account → IMAP
      Server: 10.129.98.84  Port: 143
```

### Interesting Findings Filter
The summary only shows genuinely actionable output:
- Vulnerable findings
- Anonymous login allowed
- Credentials or password hashes
- RCE indicators

---

## Adding Custom Services

Add an entry to `SERVICE_SCRIPTS` in the script:

```python
1234: {
    "name": "MyService",
    "scripts": ",".join([
        "my-script-1",
        "my-script-2",
    ]),
    "extra_args": ""   # e.g. "-sU" for UDP services
},
```
