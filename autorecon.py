#!/usr/bin/env python3
#This tool was generated with AI
"""
AutoRecon — Automated Nmap Enumeration Script
For CTFs (HackTheBox, CPTS, etc.)

Usage:
    python3 autorecon.py -t TARGET_IP
    python3 autorecon.py -t TARGET_IP -o /output/dir
    python3 autorecon.py -t 10.129.1.0/24 --sweep

Install:
    pip install python-nmap
"""

import nmap
import argparse
import os
import sys
import json
import subprocess
from datetime import datetime

# ══════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════
VERSION     = "1.0"
OUTPUT_DIR  = f"autorecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Colors
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ══════════════════════════════════════════════════════════
#  SERVICE → SCRIPT MAPPING
#  Maps port numbers to nmap scripts to run
# ══════════════════════════════════════════════════════════
SERVICE_SCRIPTS = {
    # ── FTP ──────────────────────────────────────────────
    21: {
        "name": "FTP",
        "scripts": ",".join([
            "ftp-anon",
            "ftp-syst",
            "ftp-vsftpd-backdoor",
            "ftp-proftpd-backdoor",
            "ftp-bounce",
            "ftp-libopie",
            "ftp-vuln-cve2010-4221",
        ]),
        "extra_args": ""
    },
    # ── SSH ──────────────────────────────────────────────
    22: {
        "name": "SSH",
        "scripts": ",".join([
            "ssh-auth-methods",
            "ssh2-enum-algos",
            "ssh-hostkey",
            "ssh-publickey-acceptance",
        ]),
        "extra_args": ""
    },
    # ── Telnet ───────────────────────────────────────────
    23: {
        "name": "Telnet",
        "scripts": ",".join([
            "telnet-ntlm-info",
            "banner",
        ]),
        "extra_args": ""
    },
    # ── SMTP ─────────────────────────────────────────────
    25: {
        "name": "SMTP",
        "scripts": ",".join([
            "smtp-commands",
            "smtp-enum-users",
            "smtp-ntlm-info",
            "smtp-open-relay",
            "smtp-strangeport",
            "smtp-vuln-cve2010-4344",
            "smtp-vuln-cve2011-1720",
            "smtp-vuln-cve2011-1764",
        ]),
        "extra_args": ""
    },
    # ── Finger ───────────────────────────────────────────
    79: {
        "name": "Finger",
        "scripts": ",".join([
            "finger",
        ]),
        "extra_args": ""
    },
    # ── HTTP ─────────────────────────────────────────────
    80: {
        "name": "HTTP",
        "scripts": ",".join([
            "http-title",
            "http-enum",
            "http-methods",
            "http-robots.txt",
            "http-git",
            "http-auth",
            "http-auth-finder",
            "http-headers",
            "http-security-headers",
            "http-ntlm-info",
            "http-default-accounts",
            "http-waf-detect",
            "http-waf-fingerprint",
            "http-shellshock",
            "http-vuln-cve2017-5638",
            "http-vuln-cve2014-3704",
            "http-vuln-cve2015-1635",
            "http-vuln-cve2012-1823",
            "http-vuln-cve2010-0738",
            "http-vuln-cve2010-2861",
            "http-iis-webdav-vuln",
            "http-method-tamper",
            "http-passwd",
            "http-open-redirect",
            "http-cors",
            "http-cookie-flags",
            "http-cross-domain-policy",
            "http-internal-ip-disclosure",
            "http-server-header",
            "http-favicon",
            "http-generator",
            "http-php-version",
            "http-apache-server-status",
            "http-aspnet-debug",
            "http-webdav-scan",
            "http-wordpress-enum",
            "http-wordpress-users",
            "http-drupal-enum",
            "http-drupal-enum-users",
            "http-bigip-cookie",
            "http-backup-finder",
            "http-config-backup",
            "http-trace",
            "http-useragent-tester",
            "http-vhosts",
        ]),
        "extra_args": ""
    },
    # ── Kerberos ─────────────────────────────────────────
    88: {
        "name": "Kerberos",
        "scripts": ",".join([
            "krb5-enum-users",
        ]),
        "extra_args": "--script-args krb5-enum-users.realm=DOMAIN.LOCAL"
    },
    # ── POP3 ─────────────────────────────────────────────
    110: {
        "name": "POP3",
        "scripts": ",".join([
            "pop3-capabilities",
            "pop3-ntlm-info",
        ]),
        "extra_args": ""
    },
    # ── RPC ──────────────────────────────────────────────
    111: {
        "name": "RPC",
        "scripts": ",".join([
            "rpcinfo",
            "nfs-showmount",
        ]),
        "extra_args": ""
    },
    # ── IDENT ────────────────────────────────────────────
    113: {
        "name": "IDENT",
        "scripts": ",".join([
            "auth-owners",
            "auth-spoof",
        ]),
        "extra_args": ""
    },
    # ── IMAP ─────────────────────────────────────────────
    143: {
        "name": "IMAP",
        "scripts": ",".join([
            "imap-capabilities",
            "imap-ntlm-info",
        ]),
        "extra_args": ""
    },
    # ── SNMP UDP ─────────────────────────────────────────
    161: {
        "name": "SNMP",
        "scripts": ",".join([
            "snmp-info",
            "snmp-sysdescr",
            "snmp-interfaces",
            "snmp-processes",
            "snmp-netstat",
            "snmp-win32-users",
            "snmp-win32-shares",
            "snmp-win32-services",
            "snmp-win32-software",
            "snmp-hh3c-logins",
            "snmp-ios-config",
        ]),
        "extra_args": "-sU"
    },
    # ── LDAP ─────────────────────────────────────────────
    389: {
        "name": "LDAP",
        "scripts": ",".join([
            "ldap-rootdse",
            "ldap-search",
            "ldap-novell-getpass",
        ]),
        "extra_args": ""
    },
    # ── HTTPS ────────────────────────────────────────────
    443: {
        "name": "HTTPS",
        "scripts": ",".join([
            "http-title",
            "http-enum",
            "http-methods",
            "http-robots.txt",
            "http-git",
            "http-auth",
            "http-auth-finder",
            "http-headers",
            "http-security-headers",
            "http-ntlm-info",
            "http-default-accounts",
            "http-waf-detect",
            "http-waf-fingerprint",
            "http-shellshock",
            "http-vuln-cve2017-5638",
            "http-vuln-cve2014-3704",
            "http-vuln-cve2015-1635",
            "http-vuln-cve2012-1823",
            "http-vuln-cve2010-0738",
            "http-iis-webdav-vuln",
            "http-method-tamper",
            "http-passwd",
            "http-open-redirect",
            "http-cors",
            "http-cookie-flags",
            "http-cross-domain-policy",
            "http-internal-ip-disclosure",
            "http-server-header",
            "http-favicon",
            "http-generator",
            "http-php-version",
            "http-apache-server-status",
            "http-aspnet-debug",
            "http-webdav-scan",
            "http-wordpress-enum",
            "http-wordpress-users",
            "http-drupal-enum",
            "http-bigip-cookie",
            "http-backup-finder",
            "http-config-backup",
            "http-trace",
            "http-vhosts",
            "ssl-cert",
            "ssl-enum-ciphers",
            "ssl-heartbleed",
            "rsa-vuln-roca",
        ]),
        "extra_args": ""
    },
    # ── SMTPS ────────────────────────────────────────────
    465: {
        "name": "SMTPS",
        "scripts": ",".join([
            "smtp-commands",
            "smtp-enum-users",
            "smtp-ntlm-info",
            "smtp-open-relay",
        ]),
        "extra_args": ""
    },
    # ── SUBMISSION ───────────────────────────────────────
    587: {
        "name": "SMTP-Submission",
        "scripts": ",".join([
            "smtp-commands",
            "smtp-ntlm-info",
            "smtp-open-relay",
            "smtp-enum-users",
        ]),
        "extra_args": ""
    },
    # ── LDAPS ────────────────────────────────────────────
    636: {
        "name": "LDAPS",
        "scripts": ",".join([
            "ldap-rootdse",
            "ldap-search",
            "ssl-cert",
            "ssl-enum-ciphers",
        ]),
        "extra_args": ""
    },
    # ── rsync ────────────────────────────────────────────
    873: {
        "name": "rsync",
        "scripts": ",".join([
            "rsync-list-modules",
        ]),
        "extra_args": ""
    },
    # ── IMAP SSL ─────────────────────────────────────────
    993: {
        "name": "IMAPS",
        "scripts": ",".join([
            "imap-capabilities",
            "imap-ntlm-info",
            "ssl-cert",
        ]),
        "extra_args": ""
    },
    # ── POP3 SSL ─────────────────────────────────────────
    995: {
        "name": "POP3S",
        "scripts": ",".join([
            "pop3-capabilities",
            "pop3-ntlm-info",
            "ssl-cert",
        ]),
        "extra_args": ""
    },
    # ── MSRPC ────────────────────────────────────────────
    135: {
        "name": "MSRPC",
        "scripts": ",".join([
            "msrpc-enum",
        ]),
        "extra_args": ""
    },
    # ── NetBIOS ──────────────────────────────────────────
    137: {
        "name": "NetBIOS-NS",
        "scripts": ",".join([
            "nbstat",
            "nbns-interfaces",
        ]),
        "extra_args": "-sU"
    },
    # ── SMB NetBIOS ──────────────────────────────────────
    139: {
        "name": "SMB-NetBIOS",
        "scripts": ",".join([
            "smb-os-discovery",
            "smb-security-mode",
            "smb-enum-shares",
            "smb-enum-users",
            "smb-enum-groups",
            "smb-enum-domains",
            "smb-enum-sessions",
            "smb-enum-services",
            "smb-protocols",
            "smb-system-info",
            "nbstat",
        ]),
        "extra_args": ""
    },
    # ── SMB ──────────────────────────────────────────────
    445: {
        "name": "SMB",
        "scripts": ",".join([
            "smb-os-discovery",
            "smb-security-mode",
            "smb-enum-shares",
            "smb-enum-users",
            "smb-enum-groups",
            "smb-enum-domains",
            "smb-enum-sessions",
            "smb-enum-services",
            "smb-enum-processes",
            "smb-protocols",
            "smb2-security-mode",
            "smb2-capabilities",
            "smb2-time",
            "smb-system-info",
            "smb-server-stats",
            "smb-mbenum",
            "smb-vuln-ms17-010",
            "smb-vuln-ms08-067",
            "smb-vuln-ms06-025",
            "smb-vuln-ms07-029",
            "smb-vuln-ms10-054",
            "smb-vuln-ms10-061",
            "smb-vuln-cve-2017-7494",
            "smb-vuln-cve2009-3103",
            "smb-double-pulsar-backdoor",
            "smb-vuln-webexec",
            "samba-vuln-cve-2012-1182",
        ]),
        "extra_args": ""
    },
    # ── MSSQL ────────────────────────────────────────────
    1433: {
        "name": "MSSQL",
        "scripts": ",".join([
            "ms-sql-info",
            "ms-sql-empty-password",
            "ms-sql-config",
            "ms-sql-dump-hashes",
            "ms-sql-ntlm-info",
            "ms-sql-xp-cmdshell",
            "ms-sql-hasdbaccess",
            "ms-sql-tables",
            "ms-sql-dac",
            "broadcast-ms-sql-discover",
        ]),
        "extra_args": ""
    },
    # ── Oracle ───────────────────────────────────────────
    1521: {
        "name": "Oracle",
        "scripts": ",".join([
            "oracle-tns-version",
            "oracle-sid-brute",
            "oracle-enum-users",
        ]),
        "extra_args": ""
    },
    # ── NFS ──────────────────────────────────────────────
    2049: {
        "name": "NFS",
        "scripts": ",".join([
            "nfs-showmount",
            "nfs-ls",
            "nfs-statfs",
        ]),
        "extra_args": ""
    },
    # ── MySQL ────────────────────────────────────────────
    3306: {
        "name": "MySQL",
        "scripts": ",".join([
            "mysql-info",
            "mysql-empty-password",
            "mysql-enum",
            "mysql-databases",
            "mysql-users",
            "mysql-variables",
            "mysql-dump-hashes",
            "mysql-audit",
            "mysql-vuln-cve2012-2122",
        ]),
        "extra_args": ""
    },
    # ── RDP ──────────────────────────────────────────────
    3389: {
        "name": "RDP",
        "scripts": ",".join([
            "rdp-enum-encryption",
            "rdp-ntlm-info",
            "rdp-vuln-ms12-020",
        ]),
        "extra_args": ""
    },
    # ── distcc ───────────────────────────────────────────
    3632: {
        "name": "distcc",
        "scripts": ",".join([
            "distcc-cve2004-2687",
        ]),
        "extra_args": ""
    },
    # ── PostgreSQL ───────────────────────────────────────
    5432: {
        "name": "PostgreSQL",
        "scripts": ",".join([
            "pgsql-brute",
        ]),
        "extra_args": ""
    },
    # ── VNC ──────────────────────────────────────────────
    5900: {
        "name": "VNC",
        "scripts": ",".join([
            "vnc-info",
            "realvnc-auth-bypass",
        ]),
        "extra_args": ""
    },
    # ── WinRM HTTP ───────────────────────────────────────
    5985: {
        "name": "WinRM-HTTP",
        "scripts": ",".join([
            "http-auth-finder",
            "http-ntlm-info",
        ]),
        "extra_args": ""
    },
    # ── WinRM HTTPS ──────────────────────────────────────
    5986: {
        "name": "WinRM-HTTPS",
        "scripts": ",".join([
            "http-auth-finder",
            "http-ntlm-info",
            "ssl-cert",
        ]),
        "extra_args": ""
    },
    # ── JDWP ─────────────────────────────────────────────
    5005: {
        "name": "JDWP",
        "scripts": ",".join([
            "jdwp-exec",
            "jdwp-info",
            "jdwp-inject",
            "jdwp-version",
        ]),
        "extra_args": ""
    },
    # ── IPMI UDP ─────────────────────────────────────────
    623: {
        "name": "IPMI",
        "scripts": ",".join([
            "ipmi-version",
            "ipmi-cipher-zero",
        ]),
        "extra_args": "-sU"
    },
    # ── Redis ────────────────────────────────────────────
    6379: {
        "name": "Redis",
        "scripts": ",".join([
            "redis-info",
        ]),
        "extra_args": ""
    },
    # ── IRC ──────────────────────────────────────────────
    6667: {
        "name": "IRC",
        "scripts": ",".join([
            "irc-unrealircd-backdoor",
            "irc-info",
            "irc-botnet-channels",
        ]),
        "extra_args": ""
    },
    # ── AJP Tomcat ───────────────────────────────────────
    8009: {
        "name": "AJP",
        "scripts": ",".join([
            "ajp-headers",
            "ajp-methods",
            "ajp-auth",
            "ajp-request",
        ]),
        "extra_args": ""
    },
    # ── HTTP Alt ─────────────────────────────────────────
    8080: {
        "name": "HTTP-Alt",
        "scripts": ",".join([
            "http-title",
            "http-enum",
            "http-methods",
            "http-robots.txt",
            "http-git",
            "http-auth",
            "http-auth-finder",
            "http-headers",
            "http-security-headers",
            "http-ntlm-info",
            "http-default-accounts",
            "http-waf-detect",
            "http-shellshock",
            "http-vuln-cve2017-5638",
            "http-vuln-cve2014-3704",
            "http-vuln-cve2015-1635",
            "http-iis-webdav-vuln",
            "http-method-tamper",
            "http-passwd",
            "http-open-redirect",
            "http-cors",
            "http-cookie-flags",
            "http-internal-ip-disclosure",
            "http-server-header",
            "http-favicon",
            "http-backup-finder",
            "http-config-backup",
            "http-trace",
            "http-wordpress-enum",
            "http-wordpress-users",
            "http-drupal-enum",
        ]),
        "extra_args": ""
    },
    # ── HTTPS Alt ────────────────────────────────────────
    8443: {
        "name": "HTTPS-Alt",
        "scripts": ",".join([
            "http-title",
            "http-enum",
            "http-methods",
            "http-robots.txt",
            "http-git",
            "http-auth",
            "http-auth-finder",
            "http-headers",
            "http-security-headers",
            "http-ntlm-info",
            "http-default-accounts",
            "http-waf-detect",
            "http-shellshock",
            "http-vuln-cve2017-5638",
            "http-vuln-cve2014-3704",
            "http-iis-webdav-vuln",
            "http-method-tamper",
            "http-passwd",
            "http-open-redirect",
            "http-cors",
            "http-cookie-flags",
            "http-internal-ip-disclosure",
            "http-server-header",
            "http-backup-finder",
            "http-config-backup",
            "http-trace",
            "ssl-cert",
            "ssl-enum-ciphers",
            "ssl-heartbleed",
        ]),
        "extra_args": ""
    },
    # ── AD Web Services ──────────────────────────────────
    9389: {
        "name": "AD-Web-Services",
        "scripts": ",".join([
            "http-auth-finder",
            "http-ntlm-info",
        ]),
        "extra_args": ""
    },
    # ── Global Catalog ───────────────────────────────────
    3268: {
        "name": "Global-Catalog",
        "scripts": ",".join([
            "ldap-rootdse",
            "ldap-search",
        ]),
        "extra_args": ""
    },
    # ── Global Catalog SSL ───────────────────────────────
    3269: {
        "name": "Global-Catalog-SSL",
        "scripts": ",".join([
            "ldap-rootdse",
            "ldap-search",
            "ssl-cert",
        ]),
        "extra_args": ""
    },
    # ── MongoDB ──────────────────────────────────────────
    27017: {
        "name": "MongoDB",
        "scripts": ",".join([
            "mongodb-info",
            "mongodb-databases",
        ]),
        "extra_args": ""
    },
    # ── Memcached ────────────────────────────────────────
    11211: {
        "name": "Memcached",
        "scripts": ",".join([
            "memcached-info",
        ]),
        "extra_args": ""
    },
    # ── CouchDB ──────────────────────────────────────────
    5984: {
        "name": "CouchDB",
        "scripts": ",".join([
            "couchdb-databases",
            "couchdb-stats",
        ]),
        "extra_args": ""
    },
    # ── Cassandra ────────────────────────────────────────
    9042: {
        "name": "Cassandra",
        "scripts": ",".join([
            "cassandra-info",
        ]),
        "extra_args": ""
    },
    # ── Elasticsearch ────────────────────────────────────
    9200: {
        "name": "Elasticsearch",
        "scripts": ",".join([
            "http-title",
            "http-methods",
            "http-open-proxy",
        ]),
        "extra_args": ""
    },
    # ── Docker ───────────────────────────────────────────
    2375: {
        "name": "Docker",
        "scripts": ",".join([
            "docker-version",
        ]),
        "extra_args": ""
    },
    # ── RMI ──────────────────────────────────────────────
    1099: {
        "name": "RMI",
        "scripts": ",".join([
            "rmi-dumpregistry",
            "rmi-vuln-classloader",
        ]),
        "extra_args": ""
    },
    # ── PPTP ─────────────────────────────────────────────
    1723: {
        "name": "PPTP",
        "scripts": ",".join([
            "pptp-version",
        ]),
        "extra_args": ""
    },
    # ── TFTP UDP ─────────────────────────────────────────
    69: {
        "name": "TFTP",
        "scripts": ",".join([
            "tftp-enum",
        ]),
        "extra_args": "-sU"
    },
    # ── NTP UDP ──────────────────────────────────────────
    123: {
        "name": "NTP",
        "scripts": ",".join([
            "ntp-info",
            "ntp-monlist",
        ]),
        "extra_args": "-sU"
    },
    # ── DNS TCP ──────────────────────────────────────────
    53: {
        "name": "DNS",
        "scripts": ",".join([
            "dns-zone-transfer",
            "dns-srv-enum",
            "dns-recursion",
            "dns-nsid",
            "dns-cache-snoop",
            "dns-check-zone",
            "dns-random-srcport",
            "dns-random-txid",
            "dns-nsec-enum",
            "dns-brute",
            "fcrdns",
        ]),
        "extra_args": ""
    },
}

#  HELPERS
# ══════════════════════════════════════════════════════════
def banner():
    print(f"""
{CYAN}{BOLD}
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}
{BOLD}Automated Nmap Enumeration v{VERSION}{RESET}
For authorized penetration testing only
""")


def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    if level == "info":
        print(f"{BLUE}[{ts}]{RESET} {msg}")
    elif level == "success":
        print(f"{GREEN}[{ts}] [+]{RESET} {msg}")
    elif level == "warn":
        print(f"{YELLOW}[{ts}] [!]{RESET} {msg}")
    elif level == "error":
        print(f"{RED}[{ts}] [-]{RESET} {msg}")
    elif level == "section":
        print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}{BOLD} {msg}{RESET}")
        print(f"{CYAN}{BOLD}{'='*60}{RESET}")


def save_output(output_dir, filename, content):
    """Save scan output to file."""
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath


def run_nmap_subprocess(target, args, output_dir, filename):
    """
    Run nmap directly via subprocess for cases where
    python-nmap output isn't sufficient.
    """
    cmd = f"nmap {args} {target}"
    log(f"Running: {cmd}")

    result = subprocess.run(
        cmd.split(),
        capture_output=True,
        text=True
    )

    output = result.stdout
    if result.stderr:
        output += f"\n[STDERR]\n{result.stderr}"

    filepath = save_output(output_dir, filename, output)
    log(f"Saved to: {filepath}", "success")
    return output


# ══════════════════════════════════════════════════════════
#  PHASE 1 — PORT DISCOVERY
# ══════════════════════════════════════════════════════════
def phase1_port_discovery(target, output_dir):
    """Fast TCP port discovery — find all open ports quickly."""
    log("PHASE 1 — Fast TCP Port Discovery", "section")
    log(f"Target: {target}")

    nm = nmap.PortScanner()

    # Fast scan all 65535 ports
    log("Scanning all 65535 TCP ports (--min-rate 5000)...")
    try:
        nm.scan(
            hosts=target,
            arguments="-Pn -p- --min-rate 5000 --open -T4"
        )
    except Exception as e:
        log(f"Scan error: {e}", "error")
        return []

    open_ports = []

    for host in nm.all_hosts():
        log(f"Host: {host} ({nm[host].state()})", "success")

        if 'tcp' in nm[host]:
            for port, data in nm[host]['tcp'].items():
                if data['state'] == 'open':
                    open_ports.append(port)
                    log(f"  Port {port}/tcp OPEN", "success")

    # Save raw results
    raw_output = f"Open TCP Ports on {target}:\n"
    raw_output += "\n".join([str(p) for p in open_ports])
    save_output(output_dir, "01_open_ports.txt", raw_output)

    log(f"\nFound {len(open_ports)} open TCP ports: {open_ports}", "success")
    return open_ports


# ══════════════════════════════════════════════════════════
#  PHASE 2 — SERVICE DETECTION
# ══════════════════════════════════════════════════════════
def phase2_service_detection(target, open_ports, output_dir):
    """Run -sCV on discovered open ports."""
    log("PHASE 2 — Service and Version Detection", "section")

    if not open_ports:
        log("No open ports to scan", "warn")
        return {}

    ports_str = ",".join([str(p) for p in open_ports])
    log(f"Running -sCV on ports: {ports_str}")

    output = run_nmap_subprocess(
        target=target,
        args=f"-Pn -sCV -p{ports_str}",
        output_dir=output_dir,
        filename="02_service_detection.txt"
    )

    # Parse services from output for display
    services = {}
    nm = nmap.PortScanner()
    try:
        nm.scan(
            hosts=target,
            arguments=f"-Pn -sCV -p{ports_str}"
        )
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port, data in nm[host]['tcp'].items():
                    services[port] = {
                        "name": data.get('name', 'unknown'),
                        "product": data.get('product', ''),
                        "version": data.get('version', ''),
                        "state": data.get('state', '')
                    }
                    svc_info = f"{data.get('name','')} {data.get('product','')} {data.get('version','')}".strip()
                    log(f"  {port}/tcp — {svc_info}", "success")
    except Exception as e:
        log(f"Service detection parse error: {e}", "warn")

    return services


# ══════════════════════════════════════════════════════════
#  PHASE 3 — UDP SCAN
# ══════════════════════════════════════════════════════════
def phase3_udp_scan(target, output_dir):
    """Scan top 100 UDP ports."""
    log("PHASE 3 — UDP Port Scan (Top 100)", "section")

    output = run_nmap_subprocess(
        target=target,
        args="-Pn -sU --top-ports 100",
        output_dir=output_dir,
        filename="03_udp_scan.txt"
    )

    # Check for interesting UDP ports
    interesting_udp = []
    for line in output.split('\n'):
        if '/udp' in line and 'open' in line and 'filtered' not in line:
            interesting_udp.append(line.strip())
            log(f"  {line.strip()}", "success")

    if not interesting_udp:
        log("No confirmed open UDP ports found", "warn")

    return interesting_udp


# ══════════════════════════════════════════════════════════
#  PHASE 4 — TARGETED SCRIPT ENUMERATION
# ══════════════════════════════════════════════════════════
def phase4_script_enumeration(target, open_ports, output_dir):
    """
    For each open port run the appropriate NSE scripts.
    Maps port number to script list from SERVICE_SCRIPTS.
    """
    log("PHASE 4 — Targeted NSE Script Enumeration", "section")

    results = {}

    for port in open_ports:
        if port in SERVICE_SCRIPTS:
            svc = SERVICE_SCRIPTS[port]
            svc_name = svc["name"]
            scripts  = svc["scripts"]
            extra    = svc["extra_args"]

            log(f"\n[Port {port}] {svc_name} — Running scripts...")

            # Build nmap command
            args = f"-Pn {extra} --script {scripts} -p {port}"

            output = run_nmap_subprocess(
                target=target,
                args=args,
                output_dir=output_dir,
                filename=f"04_{port}_{svc_name.lower()}_scripts.txt"
            )

            results[port] = {
                "service": svc_name,
                "scripts": scripts,
                "output": output
            }

            # Highlight interesting findings
            for line in output.split('\n'):
                keywords = [
                    "VULNERABLE", "vulnerable", "CVE-",
                    "Anonymous", "anonymous", "password",
                    "credential", "admin", "root",
                    "ERROR", "open", "uid=", "id="
                ]
                if any(kw in line for kw in keywords):
                    log(f"  [INTERESTING] {line.strip()}", "warn")

        else:
            log(f"[Port {port}] No specific scripts configured — running default scripts")
            output = run_nmap_subprocess(
                target=target,
                args=f"-Pn -sCV --script default -p {port}",
                output_dir=output_dir,
                filename=f"04_{port}_unknown_default.txt"
            )

    return results


# ══════════════════════════════════════════════════════════
#  PHASE 5 — VULNERABILITY SCAN
# ══════════════════════════════════════════════════════════
def phase5_vuln_scan(target, open_ports, output_dir):
    """Run vuln category scripts against all open ports."""
    log("PHASE 5 — Vulnerability Scan", "section")

    if not open_ports:
        log("No open ports to scan", "warn")
        return

    ports_str = ",".join([str(p) for p in open_ports])
    log(f"Running vuln scripts on ports: {ports_str}")

    output = run_nmap_subprocess(
        target=target,
        args=f"-Pn --script 'vuln and safe' -p{ports_str}",
        output_dir=output_dir,
        filename="05_vuln_scan.txt"
    )

    # Extract vulnerability findings
    vulns_found = []
    for line in output.split('\n'):
        if 'VULNERABLE' in line or 'CVE-' in line:
            vulns_found.append(line.strip())
            log(f"  [VULN] {line.strip()}", "warn")

    if not vulns_found:
        log("No vulnerabilities found in vuln scan", "info")

    return vulns_found


# ══════════════════════════════════════════════════════════
#  HOST SWEEP
# ══════════════════════════════════════════════════════════
def host_sweep(target, output_dir):
    """Ping sweep to discover live hosts on a subnet."""
    log("HOST SWEEP — Discovering Live Hosts", "section")
    log(f"Target subnet: {target}")

    output = run_nmap_subprocess(
        target=target,
        args="-sn --min-rate 5000",
        output_dir=output_dir,
        filename="00_host_sweep.txt"
    )

    live_hosts = []
    for line in output.split('\n'):
        if 'Nmap scan report for' in line:
            host = line.split()[-1].strip('()')
            # Handle "hostname (IP)" format
            if '(' in line:
                host = line.split('(')[-1].rstrip(')')
            live_hosts.append(host)
            log(f"  Live host: {host}", "success")

    log(f"\nFound {len(live_hosts)} live hosts", "success")

    # Save live hosts list
    save_output(output_dir, "00_live_hosts.txt", "\n".join(live_hosts))

    return live_hosts


# ══════════════════════════════════════════════════════════
#  SUMMARY REPORT
# ══════════════════════════════════════════════════════════
def generate_report(target, open_ports, services, script_results, vuln_results, output_dir):
    """Generate a summary report of all findings."""
    log("Generating Summary Report", "section")

    report = []
    report.append(f"AutoRecon Summary Report")
    report.append(f"Target: {target}")
    report.append(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"{'='*60}\n")

    # Open ports
    report.append("OPEN PORTS")
    report.append("-"*40)
    for port in open_ports:
        svc_name = services.get(port, {}).get('name', 'unknown')
        product  = services.get(port, {}).get('product', '')
        version  = services.get(port, {}).get('version', '')
        info     = f"{svc_name} {product} {version}".strip()
        report.append(f"  {port}/tcp — {info}")

    report.append("")

    # Script enumeration results
    report.append("SCRIPT ENUMERATION")
    report.append("-"*40)
    for port, data in script_results.items():
        report.append(f"\n  Port {port} — {data['service']}")
        report.append(f"  Scripts: {data['scripts']}")
        report.append(f"  Output file: 04_{port}_{data['service'].lower()}_scripts.txt")

    report.append("")

    # Vulnerabilities
    report.append("VULNERABILITIES FOUND")
    report.append("-"*40)
    if vuln_results:
        for vuln in vuln_results:
            report.append(f"  [!] {vuln}")
    else:
        report.append("  None found")

    report.append("")
    report.append(f"Output directory: {output_dir}")
    report.append(f"{'='*60}")

    report_text = "\n".join(report)

    filepath = save_output(output_dir, "00_summary_report.txt", report_text)
    print(f"\n{CYAN}{BOLD}{report_text}{RESET}")
    log(f"Report saved to: {filepath}", "success")


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="AutoRecon — Automated Nmap Enumeration for CPTS/HackTheBox"
    )
    parser.add_argument("-t", "--target",
        required=True,
        help="Target IP, hostname, or CIDR range")
    parser.add_argument("-o", "--output",
        default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})")
    parser.add_argument("--sweep",
        action="store_true",
        help="Perform host sweep first (for subnet targets)")
    parser.add_argument("--skip-udp",
        action="store_true",
        help="Skip UDP scan")
    parser.add_argument("--skip-vuln",
        action="store_true",
        help="Skip vulnerability scan")
    parser.add_argument("--ports-only",
        action="store_true",
        help="Only perform port discovery — no scripts")

    args = parser.parse_args()

    # Check nmap is installed
    try:
        subprocess.run(["nmap", "--version"],
            capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        log("nmap is not installed or not in PATH", "error")
        sys.exit(1)

    # Check python-nmap
    try:
        import nmap
    except ImportError:
        log("python-nmap not installed — run: pip install python-nmap", "error")
        sys.exit(1)

    # Create output directory
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    log(f"Output directory: {output_dir}")

    targets = [args.target]

    # Host sweep for subnets
    if args.sweep:
        live_hosts = host_sweep(args.target, output_dir)
        if not live_hosts:
            log("No live hosts found", "error")
            sys.exit(0)
        targets = live_hosts

    # Process each target
    for target in targets:
        if len(targets) > 1:
            log(f"\nProcessing target: {target}", "section")

        # Create per-target subdirectory for multi-host scans
        if len(targets) > 1:
            target_dir = os.path.join(output_dir, target.replace('.', '_'))
            os.makedirs(target_dir, exist_ok=True)
        else:
            target_dir = output_dir

        # Phase 1 — Port Discovery
        open_ports = phase1_port_discovery(target, target_dir)

        if not open_ports:
            log(f"No open ports found on {target}", "warn")
            continue

        if args.ports_only:
            log("Ports-only mode — skipping further enumeration")
            continue

        # Phase 2 — Service Detection
        services = phase2_service_detection(target, open_ports, target_dir)

        # Phase 3 — UDP
        if not args.skip_udp:
            phase3_udp_scan(target, target_dir)

        # Phase 4 — Script Enumeration
        script_results = phase4_script_enumeration(target, open_ports, target_dir)

        # Phase 5 — Vulnerability Scan
        vuln_results = []
        if not args.skip_vuln:
            vuln_results = phase5_vuln_scan(target, open_ports, target_dir)

        # Generate Report
        generate_report(
            target=target,
            open_ports=open_ports,
            services=services,
            script_results=script_results,
            vuln_results=vuln_results,
            output_dir=target_dir
        )

    log("\nAutorecon complete!", "success")
    log(f"All output saved to: {output_dir}", "success")


if __name__ == "__main__":
    main()
