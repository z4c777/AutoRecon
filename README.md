# AutoRecon 🔍

Automated Nmap enumeration for penetration testing. Point it at a target and it handles the rest — port discovery, service detection, targeted NSE scripts, and a clean summary report.

Built for HackTheBox CPTS and CTF engagements.

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
git clone https://github.com/yourrepo/autorecon
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
| `-o` | Custom output directory |
| `--sweep` | Ping sweep subnet first, scan each live host |
| `--skip-udp` | Skip UDP scan |
| `--skip-vuln` | Skip vulnerability scan |
| `--ports-only` | Port discovery only — no scripts |
| `--oA` | Save nmap output in all formats (.nmap .gnmap .xml) |

### Examples

```bash
# Single target
python3 autorecon.py -t 10.129.98.84

# Subnet — discover and scan all live hosts
python3 autorecon.py -t 10.129.1.0/24 --sweep

# Fast scan — skip UDP and vuln scan
python3 autorecon.py -t 10.129.98.84 --skip-udp --skip-vuln

# Save nmap output in all formats
python3 autorecon.py -t 10.129.98.84 --oA

# Custom output directory
python3 autorecon.py -t 10.129.98.84 -o /home/user/htb/machinename
```

---

## How It Works

The scan runs in 5 phases:

```
Phase 1  Fast TCP port discovery    nmap -p- --min-rate 5000
Phase 2  Service detection          nmap -sCV on open ports only
Phase 3  UDP scan                   nmap -sU --top-ports 100
Phase 4  NSE script enumeration     Targeted scripts per service
Phase 5  Vulnerability scan         nmap --script 'vuln and safe'
```

---

## Output

Every scan creates a timestamped folder named after the target:

```
autorecon_10.129.98.84_20260805_224943/
├── 00_summary_report.txt     All findings in one place
├── 01_open_ports.txt         Open TCP ports
├── 02_service_detection.txt  Version and banner info
├── 03_udp_scan.txt           UDP results
├── 04_21_ftp_scripts.txt     Per-port script output
├── 04_22_ssh_scripts.txt
├── 04_80_http_scripts.txt
├── 04_445_smb_scripts.txt
└── 05_vuln_scan.txt          Vulnerability findings
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

### v2.0
- Output folder now includes target IP in name
- `--oA` flag to save nmap output in all formats
- Non-standard port detection — matches by service name not just port number
- Post-scan tips printed after each service
- Weak SSH algorithm detection
- Report summary cleaned up — no script lists, actionable findings only
- Removed low-value scripts: `http-useragent-tester`, `http-bigip-cookie`, `http-cross-domain-policy`
- `NOT VULNERABLE` false positive fix
- 55 total service mappings

### v1.0
- Initial release

---

## Disclaimer

For authorized penetration testing and CTF environments only.

---

## License

MIT
