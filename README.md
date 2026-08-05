# AutoRecon 🔍

Automated Nmap enumeration script for penetration testing. Performs multi-phase scanning — discovers open ports, detects services, runs targeted NSE scripts, and produces a clean summary report.

Built for HackTheBox CPTS and general CTF/pentest engagements.

---

## Features

- **5-phase scanning pipeline** — port discovery → service detection → UDP → script enumeration → vuln scan
- **Automatic script selection** — maps 40+ services to their most relevant NSE scripts
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
chmod +x autorecon.py
```

---

## Usage

```bash
python3 autorecon.py -t TARGET [options]
```

### Basic Examples

```bash
# Full scan against single target
python3 autorecon.py -t 10.129.1.5

# Custom output directory
python3 autorecon.py -t 10.129.1.5 -o /home/user/htb/machine_name

# Subnet sweep — discover live hosts then scan each one
python3 autorecon.py -t 10.129.1.0/24 --sweep

# Skip UDP and vuln scan for speed
python3 autorecon.py -t 10.129.1.5 --skip-udp --skip-vuln

# Port discovery only — no script enumeration
python3 autorecon.py -t 10.129.1.5 --ports-only
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
For each open port, looks up the service in the script mapping and runs the appropriate NSE scripts automatically.

### Phase 5 — Vulnerability Scan
Runs the `vuln and safe` NSE categories against all open ports to detect known vulnerabilities.

```
nmap -Pn --script 'vuln and safe' -p<OPEN_PORTS> TARGET
```

---

## Service → Script Mapping

The script automatically selects NSE scripts based on the open port:

| Port | Service | Scripts Run |
|------|---------|-------------|
| 21 | FTP | ftp-anon, ftp-vsftpd-backdoor, ftp-proftpd-backdoor |
| 22 | SSH | ssh-auth-methods, ssh2-enum-algos, ssh-hostkey |
| 25 | SMTP | smtp-commands, smtp-enum-users, smtp-ntlm-info |
| 53 | DNS | dns-zone-transfer, dns-srv-enum, dns-recursion |
| 80 | HTTP | http-title, http-enum, http-methods, http-git, http-robots.txt, http-waf-detect |
| 88 | Kerberos | krb5-enum-users |
| 111 | RPC | rpcinfo |
| 135 | MSRPC | msrpc-enum |
| 139 | NetBIOS | smb-os-discovery, smb-enum-shares, nbstat |
| 143 | IMAP | imap-capabilities, imap-ntlm-info |
| 161 | SNMP (UDP) | snmp-info, snmp-interfaces, snmp-processes, snmp-win32-users |
| 389 | LDAP | ldap-rootdse, ldap-search |
| 443 | HTTPS | http-enum, ssl-cert, ssl-enum-ciphers, http-waf-detect |
| 445 | SMB | smb-os-discovery, smb-enum-shares, smb-enum-users, smb-vuln-ms17-010, smb-double-pulsar-backdoor |
| 636 | LDAPS | ldap-rootdse, ldap-search, ssl-cert |
| 873 | rsync | rsync-list-modules |
| 1433 | MSSQL | ms-sql-info, ms-sql-empty-password, ms-sql-dump-hashes, ms-sql-xp-cmdshell |
| 2049 | NFS | nfs-showmount, nfs-ls, nfs-statfs |
| 3268 | Global Catalog | ldap-rootdse, ldap-search |
| 3306 | MySQL | mysql-info, mysql-empty-password, mysql-databases, mysql-dump-hashes |
| 3389 | RDP | rdp-enum-encryption, rdp-ntlm-info, rdp-vuln-ms12-020 |
| 3632 | distcc | distcc-cve2004-2687 (RCE) |
| 5432 | PostgreSQL | pgsql-brute |
| 5900 | VNC | vnc-info, realvnc-auth-bypass |
| 5985 | WinRM | http-auth-finder |
| 6379 | Redis | redis-info |
| 6667 | IRC | irc-unrealircd-backdoor |
| 8080 | HTTP-Alt | http-title, http-enum, http-methods, http-default-accounts |
| 27017 | MongoDB | mongodb-info, mongodb-databases |

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

To add a new service to the script mapping open `autorecon.py` and add an entry to the `SERVICE_SCRIPTS` dictionary:

```python
SERVICE_SCRIPTS = {
    # existing entries...

    # Add your custom service
    1234: {
        "name": "MyService",
        "scripts": "my-script-1,my-script-2,my-script-3",
        "extra_args": ""        # Optional nmap flags e.g. "-sU" for UDP
    },
}
```

The script will automatically run your custom scripts whenever port 1234 is found open.

---

## Tips for CPTS

- Run with `--skip-udp --skip-vuln` for a fast first pass to identify the attack surface
- Run the full scan in the background while manually investigating interesting ports
- All output is saved to files — paste directly into your Obsidian machine template
- The summary report shows interesting findings flagged in real time — check those first
- For Active Directory targets make sure ports 88, 389, 445, 3268, and 5985 are covered

---

## Disclaimer

This tool is for authorized penetration testing and CTF environments only. Do not use against systems you do not have explicit written permission to test.

---

## License

MIT
