# AutoRecon 🔍

Automated Nmap enumeration for penetration testing. Point it at a target and it handles the rest — port discovery, service detection, targeted NSE scripts, and a clean summary report.

Built for HackTheBox CTFs.

## Disclaimer: This tool was generated with AI.

---

## Quick Start

```bash
# Install
pip install python-nmap
sudo apt install nmap

# Run
python3 autorecon.py -t 10.129.98.84
```

Output folder is created automatically:
```
autorecon_10.129.98.84_20260805_224943/
```

---

## Installation

```bash
git clone https://github.com/z4c777/AutoRecon
cd autorecon
pip install python-nmap
chmod +x autorecon.py
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

The scan runs in up to 7 phases:

```
Phase 0  DNS enumeration            Record lookup + zone transfer (opt-in via --domain)
Phase 1  Fast TCP port discovery    nmap -p- --min-rate 5000
Phase 2  Service detection          nmap -sCV on open ports only
Phase 3  UDP scan  ┐ concurrent     nmap -sU --top-ports 100
Phase 4  NSE scripts┘               All scripts in ONE nmap call
Phase 5  Vulnerability scan         nmap --script 'vuln and safe' (opt-in via --vuln)
Phase 6  Vhost discovery            ffuf baseline method (opt-in via --vhost)
```

Phase 3 and Phase 4 run **concurrently** — UDP scan runs in the background while NSE scripts run in the foreground. Cuts total scan time significantly.

Phase 4 combines all scripts for all open ports into a single nmap command instead of one per port — cuts Phase 4 from ~10 minutes to ~90 seconds on a typical machine.

---

## Output

Every scan creates a timestamped folder named after the target:

```
autorecon_10.129.98.84_20260805_224943/
├── 00_dns_enum.txt              DNS record enumeration (Phase 0)
├── 00_dns_axfr_10_129_98_84.txt Zone transfer output if successful
├── 00_summary_report.txt        All findings in one place
├── 10_129_98_84_notes.md        Obsidian-ready markdown report
├── 01_open_ports.txt            Open TCP ports
├── 02_service_detection.txt     Version and banner info
├── 03_udp_scan.txt              UDP results
├── 04_tcp_scripts.txt           All TCP NSE script output
├── 04_udp_scripts.txt           All UDP NSE script output
├── 04_111_rpcinfo.txt           rpcinfo binary output (if RPC found)
├── 05_vuln_scan.txt             Vulnerability findings (--vuln only)
└── 06_vhosts_port80.txt         Vhost discovery results (--vhost only)
```

Note: `.autorecon_state.json` is created during the scan to track progress and deleted automatically on completion. If the scan is interrupted re-run the same command to resume.

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

Scripts are automatically selected based on the detected service — even on non-standard ports. For example FTP running on port 2121 still gets FTP scripts.

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

### Mail

| Port | Service | Key Scripts |
|------|---------|-------------|
| 25 | SMTP | smtp-commands, smtp-enum-users, smtp-open-relay, smtp-vuln-* |
| 110 | POP3 | pop3-capabilities, pop3-ntlm-info |
| 143 | IMAP | imap-capabilities, imap-ntlm-info |
| 465 | SMTPS | smtp-commands, smtp-enum-users |
| 587 | Submission | smtp-commands, smtp-open-relay |
| 993 | IMAPS | imap-capabilities, ssl-cert |
| 995 | POP3S | pop3-capabilities, ssl-cert |

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

### Databases

| Port | Service | Key Scripts |
|------|---------|-------------|
| 1433 | MSSQL | ms-sql-info, ms-sql-empty-password, ms-sql-xp-cmdshell |
| 1521 | Oracle | oracle-tns-version, oracle-sid-brute |
| 3306 | MySQL | mysql-info, mysql-empty-password, mysql-dump-hashes |
| 5432 | PostgreSQL | pgsql-brute |
| 6379 | Redis | redis-info |
| 27017 | MongoDB | mongodb-info, mongodb-databases |
| 5984 | CouchDB | couchdb-databases, couchdb-stats |
| 9200 | Elasticsearch | http-title, http-methods |
| 11211 | Memcached | memcached-info |

### Infrastructure / Dev

| Port | Service | Key Scripts |
|------|---------|-------------|
| 161 | SNMP (UDP) | snmp-info, snmp-processes, snmp-win32-users, snmp-win32-shares |
| 623 | IPMI (UDP) | ipmi-version, ipmi-cipher-zero |
| 1099 | RMI | rmi-dumpregistry, rmi-vuln-classloader |
| 2049 | NFS | nfs-showmount, nfs-ls, nfs-statfs |
| 2375 | Docker | docker-version |
| 3632 | distcc | distcc-cve2004-2687 (RCE) |
| 5005 | JDWP | jdwp-exec, jdwp-info, jdwp-inject (RCE) |
| 5900 | VNC | vnc-info, realvnc-auth-bypass |
| 6667 | IRC | irc-unrealircd-backdoor |
| 9042 | Cassandra | cassandra-info |

---

## Smart Features

### Concurrent Scanning
Phase 3 (UDP) and Phase 4 (NSE scripts) run simultaneously — UDP scan runs in the background while scripts run in the foreground. No waiting for UDP to finish before scripts start.

### Resume Interrupted Scans
Scan progress is saved after each phase to `.autorecon_state.json`. If the scan crashes or is interrupted just re-run the same command:

```bash
python3 autorecon.py -t 10.129.98.84  # resumes automatically
# Resuming scan — skipping completed phases up to Phase 2
# Phase 1 already complete — loaded 11 ports from state
```

State file is deleted automatically on successful completion.

### Markdown Report
Every scan generates an Obsidian-compatible markdown report ready to paste into your notes:

```
10_129_98_84_notes.md
  # 10.129.98.84
  ## Host Info
  ## Open Ports
  ## Interesting Findings
  ## Exploitation      ← pre-populated placeholders
  ## Privilege Escalation
  ## Flags
  ## Credentials Found
  ## Rabbit Holes
```

### /etc/hosts Auto-Update
When `--domain` is set the script prompts to add discovered hostnames to `/etc/hosts` after the scan:

```
Discovered hostnames not in /etc/hosts:
  10.129.98.84  inlanefreight.local

Add 1 hostname(s) to /etc/hosts? (y/n):
```

Requires `sudo` — prints manual command if permission is denied.

### Non-Standard Port Detection
If a service runs on an unusual port the script detects it by service name and applies the right scripts automatically.

```
FTP on port 2121  →  ftp-anon, ftp-vsftpd-backdoor etc
HTTP on port 8888 →  Full HTTP script suite
MySQL on port 3307 → mysql-info, mysql-dump-hashes etc
```

### Post-Scan Tips
After scanning each service actionable next steps are printed automatically. Example for IMAP:

```
[TIP] IMAP found — if on a Linux host try Evolution mail client:
      sudo apt install evolution
      Launch Evolution → New Account → IMAP
      Server: 10.129.98.84  Port: 143
```

### Weak SSH Algorithm Detection
`ssh2-enum-algos` runs against SSH but only flags deprecated algorithms:

| Algorithm | Reason flagged |
|-----------|---------------|
| `arcfour` | RC4 — cryptographically broken |
| `3des-cbc` | Sweet32 vulnerable |
| `diffie-hellman-group1-sha1` | Logjam vulnerable |
| `hmac-md5` | MD5 — broken |
| `ssh-dss` | DSA — deprecated |

Modern algorithms are silently skipped — no noise.

### Interesting Findings Filter
The summary only shows genuinely actionable output:
- Vulnerable findings
- Anonymous login allowed
- Credentials or password hashes
- RCE indicators

False positives filtered out:
- SSH algorithm lists
- `NOT VULNERABLE` lines
- OpenSSH identifier strings

### Active Checks
Beyond NSE scripts the tool runs these active checks automatically:

| Service | Check | Tool |
|---------|-------|------|
| SSH | Default credential test | paramiko |
| SMTP | User enumeration via VRFY | socket |
| RPC | Service enumeration | rpcinfo binary |

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

---

## CPTS Tips

- Run `--skip-udp --skip-vuln` for a fast first pass to map the attack surface
- Run the full scan in the background while manually investigating
- Check `00_summary_report.txt` first — interesting findings are flagged automatically
- For AD targets confirm ports 88, 389, 445, 3268, 5985 are in scope
- IPMI on UDP 623 — cipher zero vulnerability gives plaintext credentials
- distcc on 3632 and JDWP on 5005 — both have active RCE scripts

---

## Changelog

### v2.1
- Phase 0 DNS enumeration — A, AAAA, MX, NS, TXT, SOA, SRV record lookup
- Zone transfer via `dig axfr` against target and all discovered nameservers
- `--domain` / `-d` flag for explicit domain targeting
- Domain auto-derived from hostname target or reverse DNS if no flag provided
- Post-scan tip for subdomain brute force with dnsrecon/dnsx

### v2.0

**Performance**
- Phase 4 now runs all scripts in a single nmap command — ~10 min → ~2-3 min per host
- Removed duplicate python-nmap scan in Phase 2 — output parsed directly from subprocess
- Phase 5 vulnerability scan is now opt-in via `--vuln` — disabled by default

**Output**
- Folder name includes target IP and timestamp — `autorecon_10.129.98.84_20260805_224943`
- `--oA` flag saves nmap output in all three formats alongside `.txt`
- Summary report shows nmap-style script output per port
- Report no longer lists every script that ran — actionable findings only

**Script Selection**
- Non-standard port detection — scripts matched by service name if port not in standard mapping
  - e.g. FTP on port 2121 still gets `ftp-anon`, `ftp-vsftpd-backdoor` etc
- `get_scripts_for_port()` helper handles port → service name → script lookup
- 55 total service mappings (up from 40)

**False Positive Fixes**
- `@openssh.com` algorithm lines no longer flagged as interesting
- `NOT VULNERABLE` lines excluded from interesting findings
- `password` keyword tightened to `password:` — no longer matches SSH auth method listings
- SSH algorithm output filtered from report — weak algorithms still flagged as `[WEAK ALGO]`

**SSH**
- `ssh2-enum-algos` retained but only flags deprecated algorithms:
  `arcfour`, `3des-cbc`, `blowfish-cbc`, `diffie-hellman-group1-sha1`, `hmac-md5`, `ssh-dss`

**Post-Scan Tips**
- Actionable next steps printed after each service is scanned
- IMAP tip includes Evolution mail client setup
- Tips cover: FTP, SMB, SMTP, DNS, RPC/NFS, HTTP/HTTPS, SNMP, MySQL, MSSQL, RDP, Redis, VNC, LDAP, distcc, JDWP, WinRM, IPMI

**Removed Low-Value Scripts**
- `http-useragent-tester` — noise, no pentest value
- `http-bigip-cookie` — F5 only, irrelevant on HTB/CPTS
- `http-cross-domain-policy` — Flash is dead

### v1.0
- Initial release with 40 service mappings

---

## Disclaimer

For authorized penetration testing and CTF environments only.

---

## License

MIT
