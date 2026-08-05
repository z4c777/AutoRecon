# AutoRecon 🔍

Automated Nmap enumeration script for penetration testing. Performs multi-phase scanning — discovers open ports, detects services, runs targeted NSE scripts, and produces a clean summary report.

Built for CTF's such as HackTheBox.

---

## Features

- **5-phase scanning pipeline** — port discovery → service detection → UDP → script enumeration → vuln scan
- **Automatic script selection** — maps 55 services to their most relevant NSE scripts
- **Subnet support** — ping sweep then scan each live host
- **Color coded terminal output** — highlights interesting findings in real time
- **Organized output** — one file per scan phase, per port
- **Summary report** — aggregated findings at the end of every scan

---

## Requirements

```bash
# nmap must be installed
sudo apt install nmap        # Kali/Debian
brew install nmap            # Mac

# Python dependency
pip install python-nmap
```

---

## Installation

```bash
git clone https://github.com/yourrepo/autorecon
cd autorecon
pip install python-nmap
chmod +x autorecon_v2.py
```

---

## Usage

```bash
python3 autorecon_v2.py -t TARGET [options]
```

### Basic Examples

```bash
# Full scan against single target
python3 autorecon_v2.py -t 10.129.1.5

# Custom output directory
python3 autorecon_v2.py -t 10.129.1.5 -o /home/user/htb/machine_name

# Subnet sweep — discover live hosts then scan each one
python3 autorecon_v2.py -t 10.129.1.0/24 --sweep

# Skip UDP and vuln scan for speed
python3 autorecon_v2.py -t 10.129.1.5 --skip-udp --skip-vuln

# Port discovery only — no script enumeration
python3 autorecon_v2.py -t 10.129.1.5 --ports-only
```

### All Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target IP, hostname, or CIDR range (required) |
| `-o`, `--output` | Output directory (default: autorecon_TIMESTAMP) |
| `--sweep` | Ping sweep subnet first, then scan each live host |
| `--skip-udp` | Skip UDP scan |
| `--skip-vuln` | Skip vulnerability scan |
| `--ports-only` | Port discovery only — no service detection or scripts |

---

## Scan Phases

### Phase 1 — Fast TCP Port Discovery
Scans all 65535 TCP ports using `--min-rate 5000` to find open ports quickly before running heavier scans.

```
nmap -Pn -p- --min-rate 5000 --open -T4 TARGET
```

### Phase 2 — Service and Version Detection
Runs `-sCV` only against confirmed open ports — significantly faster than full `-sCV -p-`.

```
nmap -Pn -sCV -p<OPEN_PORTS> TARGET
```

### Phase 3 — UDP Scan
Scans top 100 UDP ports to catch commonly missed services like SNMP, DNS, TFTP, NTP, and IPMI.

```
nmap -Pn -sU --top-ports 100 TARGET
```

### Phase 4 — Targeted NSE Script Enumeration
For each open port looks up the service in the script mapping and runs the appropriate NSE scripts automatically.

### Phase 5 — Vulnerability Scan
Runs the `vuln and safe` NSE categories against all open ports to detect known vulnerabilities.

```
nmap -Pn --script 'vuln and safe' -p<OPEN_PORTS> TARGET
```

---

## Service → Script Mapping (55 Services)

### Network Services

| Port | Service | Scripts Run |
|------|---------|-------------|
| 21 | FTP | ftp-anon, ftp-syst, ftp-vsftpd-backdoor, ftp-proftpd-backdoor, ftp-bounce, ftp-libopie, ftp-vuln-cve2010-4221 |
| 22 | SSH | ssh-auth-methods, ssh2-enum-algos, ssh-hostkey, ssh-publickey-acceptance |
| 23 | Telnet | telnet-ntlm-info, banner |
| 53 | DNS | dns-zone-transfer, dns-srv-enum, dns-recursion, dns-nsid, dns-cache-snoop, dns-check-zone, dns-random-srcport, dns-random-txid, dns-nsec-enum, dns-brute, fcrdns |
| 69 | TFTP (UDP) | tftp-enum |
| 79 | Finger | finger |
| 111 | RPC | rpcinfo, nfs-showmount |
| 113 | IDENT | auth-owners, auth-spoof |
| 123 | NTP (UDP) | ntp-info, ntp-monlist |
| 873 | rsync | rsync-list-modules |

### Mail Services

| Port | Service | Scripts Run |
|------|---------|-------------|
| 25 | SMTP | smtp-commands, smtp-enum-users, smtp-ntlm-info, smtp-open-relay, smtp-strangeport, smtp-vuln-cve2010-4344, smtp-vuln-cve2011-1720, smtp-vuln-cve2011-1764 |
| 110 | POP3 | pop3-capabilities, pop3-ntlm-info |
| 143 | IMAP | imap-capabilities, imap-ntlm-info |
| 465 | SMTPS | smtp-commands, smtp-enum-users, smtp-ntlm-info, smtp-open-relay |
| 587 | SMTP Submission | smtp-commands, smtp-ntlm-info, smtp-open-relay, smtp-enum-users |
| 993 | IMAPS | imap-capabilities, imap-ntlm-info, ssl-cert |
| 995 | POP3S | pop3-capabilities, pop3-ntlm-info, ssl-cert |

### Web Services

| Port | Service | Scripts Run |
|------|---------|-------------|
| 80 | HTTP | http-title, http-enum, http-methods, http-robots.txt, http-git, http-auth, http-auth-finder, http-headers, http-security-headers, http-ntlm-info, http-default-accounts, http-waf-detect, http-waf-fingerprint, http-shellshock, http-vuln-cve2017-5638, http-vuln-cve2014-3704, http-vuln-cve2015-1635, http-vuln-cve2012-1823, http-vuln-cve2010-0738, http-vuln-cve2010-2861, http-iis-webdav-vuln, http-method-tamper, http-passwd, http-open-redirect, http-cors, http-cookie-flags, http-cross-domain-policy, http-internal-ip-disclosure, http-server-header, http-favicon, http-generator, http-php-version, http-apache-server-status, http-aspnet-debug, http-webdav-scan, http-wordpress-enum, http-wordpress-users, http-drupal-enum, http-drupal-enum-users, http-bigip-cookie, http-backup-finder, http-config-backup, http-trace, http-vhosts |
| 443 | HTTPS | All HTTP scripts + ssl-cert, ssl-enum-ciphers, ssl-heartbleed, rsa-vuln-roca |
| 8080 | HTTP-Alt | All HTTP scripts |
| 8443 | HTTPS-Alt | All HTTP scripts + ssl-cert, ssl-enum-ciphers, ssl-heartbleed |
| 8009 | AJP/Tomcat | ajp-headers, ajp-methods, ajp-auth, ajp-request |

### Windows / Active Directory

| Port | Service | Scripts Run |
|------|---------|-------------|
| 88 | Kerberos | krb5-enum-users |
| 135 | MSRPC | msrpc-enum |
| 137 | NetBIOS-NS (UDP) | nbstat, nbns-interfaces |
| 139 | SMB/NetBIOS | smb-os-discovery, smb-security-mode, smb-enum-shares, smb-enum-users, smb-enum-groups, smb-enum-domains, smb-enum-sessions, smb-enum-services, smb-protocols, smb-system-info, nbstat |
| 389 | LDAP | ldap-rootdse, ldap-search, ldap-novell-getpass |
| 445 | SMB | smb-os-discovery, smb-security-mode, smb-enum-shares, smb-enum-users, smb-enum-groups, smb-enum-domains, smb-enum-sessions, smb-enum-services, smb-enum-processes, smb-protocols, smb2-security-mode, smb2-capabilities, smb2-time, smb-system-info, smb-server-stats, smb-mbenum, smb-vuln-ms17-010, smb-vuln-ms08-067, smb-vuln-ms06-025, smb-vuln-ms07-029, smb-vuln-ms10-054, smb-vuln-ms10-061, smb-vuln-cve-2017-7494, smb-vuln-cve2009-3103, smb-double-pulsar-backdoor, smb-vuln-webexec, samba-vuln-cve-2012-1182 |
| 636 | LDAPS | ldap-rootdse, ldap-search, ssl-cert, ssl-enum-ciphers |
| 3268 | Global Catalog | ldap-rootdse, ldap-search |
| 3269 | Global Catalog SSL | ldap-rootdse, ldap-search, ssl-cert |
| 3389 | RDP | rdp-enum-encryption, rdp-ntlm-info, rdp-vuln-ms12-020 |
| 5985 | WinRM HTTP | http-auth-finder, http-ntlm-info |
| 5986 | WinRM HTTPS | http-auth-finder, http-ntlm-info, ssl-cert |
| 9389 | AD Web Services | http-auth-finder, http-ntlm-info |

### Databases

| Port | Service | Scripts Run |
|------|---------|-------------|
| 1433 | MSSQL | ms-sql-info, ms-sql-empty-password, ms-sql-config, ms-sql-dump-hashes, ms-sql-ntlm-info, ms-sql-xp-cmdshell, ms-sql-hasdbaccess, ms-sql-tables, ms-sql-dac, broadcast-ms-sql-discover |
| 1521 | Oracle | oracle-tns-version, oracle-sid-brute, oracle-enum-users |
| 3306 | MySQL | mysql-info, mysql-empty-password, mysql-enum, mysql-databases, mysql-users, mysql-variables, mysql-dump-hashes, mysql-audit, mysql-vuln-cve2012-2122 |
| 5432 | PostgreSQL | pgsql-brute |
| 6379 | Redis | redis-info |
| 11211 | Memcached | memcached-info |
| 27017 | MongoDB | mongodb-info, mongodb-databases |
| 5984 | CouchDB | couchdb-databases, couchdb-stats |
| 9042 | Cassandra | cassandra-info |
| 9200 | Elasticsearch | http-title, http-methods |

### Remote Access / Management

| Port | Service | Scripts Run |
|------|---------|-------------|
| 161 | SNMP (UDP) | snmp-info, snmp-sysdescr, snmp-interfaces, snmp-processes, snmp-netstat, snmp-win32-users, snmp-win32-shares, snmp-win32-services, snmp-win32-software, snmp-hh3c-logins, snmp-ios-config |
| 623 | IPMI (UDP) | ipmi-version, ipmi-cipher-zero |
| 1723 | PPTP | pptp-version |
| 5900 | VNC | vnc-info, realvnc-auth-bypass |

### Development / Infrastructure

| Port | Service | Scripts Run |
|------|---------|-------------|
| 1099 | RMI | rmi-dumpregistry, rmi-vuln-classloader |
| 2049 | NFS | nfs-showmount, nfs-ls, nfs-statfs |
| 2375 | Docker | docker-version |
| 3632 | distcc | distcc-cve2004-2687 (RCE) |
| 5005 | JDWP | jdwp-exec, jdwp-info, jdwp-inject, jdwp-version |
| 6667 | IRC | irc-unrealircd-backdoor, irc-info, irc-botnet-channels |

> Ports not in the mapping fall back to default NSE scripts (`-sCV --script default`).

---

## Output Structure

Every scan creates a timestamped output directory:

```
autorecon_20260805_120000/
├── 00_summary_report.txt        Overview of all findings
├── 00_live_hosts.txt            Live hosts found (sweep mode only)
├── 01_open_ports.txt            All open TCP ports
├── 02_service_detection.txt     -sCV output
├── 03_udp_scan.txt              Top 100 UDP results
├── 04_21_ftp_scripts.txt        Per-port NSE script output
├── 04_22_ssh_scripts.txt
├── 04_80_http_scripts.txt
├── 04_445_smb_scripts.txt
└── 05_vuln_scan.txt             Vulnerability scan findings
```

For subnet sweeps each host gets its own subdirectory:

```
autorecon_20260805_120000/
├── 00_live_hosts.txt
├── 10_129_1_5/
│   ├── 00_summary_report.txt
│   ├── 01_open_ports.txt
│   └── ...
└── 10_129_1_10/
    ├── 00_summary_report.txt
    ├── 01_open_ports.txt
    └── ...
```

---

## Adding Custom Services

To add a new service open `autorecon_v2.py` and add an entry to the `SERVICE_SCRIPTS` dictionary:

```python
SERVICE_SCRIPTS = {
    # existing entries...

    # Add your custom service
    1234: {
        "name": "MyService",
        "scripts": ",".join([
            "my-script-1",
            "my-script-2",
            "my-script-3",
        ]),
        "extra_args": ""        # Optional nmap flags e.g. "-sU" for UDP
    },
}
```

The script will automatically run your custom scripts whenever port 1234 is found open.

---

## Changelog

### v2.0
- **55 service mappings** (up from 40)
- Added missing HTTP vuln scripts: shellshock, Struts, Drupageddon, MS15-034, IIS WebDAV, PHP-CGI
- Added HTTP enumeration scripts: auth-finder, waf-fingerprint, bigip-cookie, backup-finder, config-backup, vhosts, cors, cookie-flags, passwd, method-tamper
- Added SSL scripts: ssl-heartbleed, rsa-vuln-roca
- Expanded SMB coverage: all enum scripts, all vuln scripts including webexec and samba CVE
- Expanded MSSQL: hasdbaccess, tables, dac, broadcast discovery
- Expanded MySQL: variables, audit, CVE-2012-2122
- Added JDWP: inject, version scripts
- Added IRC: botnet-channels
- Added AJP: auth, request
- Added SNMP: hh3c-logins, ios-config
- New services: TFTP, NTP, NetBIOS-NS, IPMI, IMAPS, POP3S, RMI, PPTP, Docker, CouchDB, Cassandra, Elasticsearch, Memcached

### v1.0
- Initial release with 40 service mappings
---

## Disclaimer

This tool is for authorized penetration testing and CTF environments only. Do not use against systems you do not have explicit written permission to test.

---

## License

MIT
