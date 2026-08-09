#!/usr/bin/env python3
"""
ZRecon — Automated Nmap Enumeration Script
For authorized penetration testing only (HackTheBox, CPTS, etc.)

Usage:
    python3 zrecon.py -t TARGET_IP
    python3 zrecon.py -t TARGET_IP -o /output/dir
    python3 zrecon.py -t 10.129.1.0/24 --sweep

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
from concurrent.futures import ThreadPoolExecutor, as_completed

# ══════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════
VERSION     = "1.0"
OUTPUT_DIR  = f"zrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
USE_OA      = False   # Set to True via --oA flag

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
                        "http-backup-finder",
            "http-config-backup",
            "http-trace",
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


# ══════════════════════════════════════════════════════════
#  SERVICE NAME -> SCRIPT MAPPING
#  Allows script selection by detected service name
#  so non-standard ports still get the right scripts
#  e.g. FTP on port 2121 still runs ftp-* scripts
# ══════════════════════════════════════════════════════════
SERVICE_NAME_MAP = {
    "ftp": 21, "ftp-data": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25, "smtps": 465, "submission": 587,
    "dns": 53, "domain": 53,
    "http": 80, "http-alt": 8080, "http-proxy": 8080,
    "https": 443, "https-alt": 8443,
    "kerberos": 88, "kpasswd5": 88,
    "pop3": 110, "pop3s": 995,
    "rpc": 111, "sunrpc": 111,
    "ident": 113, "auth": 113,
    "imap": 143, "imaps": 993,
    "snmp": 161,
    "ldap": 389, "ldaps": 636,
    "rsync": 873,
    "msrpc": 135, "epmap": 135,
    "netbios-ns": 137, "netbios-ssn": 139,
    "smb": 445, "microsoft-ds": 445,
    "mssql": 1433, "ms-sql-s": 1433,
    "oracle": 1521, "oracle-tns": 1521,
    "nfs": 2049,
    "mysql": 3306,
    "rdp": 3389, "ms-wbt-server": 3389,
    "distcc": 3632,
    "postgresql": 5432, "postgres": 5432,
    "vnc": 5900, "rfb": 5900,
    "wsman": 5985, "wsmans": 5986,
    "jdwp": 5005,
    "ipmi": 623, "asf-rmcp": 623,
    "redis": 6379,
    "irc": 6667,
    "ajp": 8009, "ajp13": 8009,
    "globalcatldap": 3268, "globalcatldaps": 3269,
    "mongodb": 27017,
    "memcached": 11211,
    "couchdb": 5984,
    "cassandra": 9042,
    "elasticsearch": 9200,
    "docker": 2375,
    "rmi": 1099, "java-rmi": 1099,
    "pptp": 1723,
    "tftp": 69,
    "ntp": 123,
    "finger": 79,
}


def get_scripts_for_port(port, services):
    """
    Return correct script config for a port.
    1. Check port number directly (standard ports)
    2. Fall back to detected service name (non-standard ports)
    3. Check product field as last resort
    e.g. FTP on port 2121 will still get ftp-* scripts
    """
    # Direct port match
    if port in SERVICE_SCRIPTS:
        return SERVICE_SCRIPTS[port]

    svc_data = services.get(port, {})
    svc_name = svc_data.get('name', '').lower()
    product  = svc_data.get('product', '').lower()

    # Match by service name
    if svc_name in SERVICE_NAME_MAP:
        mapped_port = SERVICE_NAME_MAP[svc_name]
        if mapped_port in SERVICE_SCRIPTS:
            log(f"  [*] Port {port} non-standard — matched service '{svc_name}' to port {mapped_port} scripts")
            return SERVICE_SCRIPTS[mapped_port]

    # Match by product string
    for keyword, mapped_port in SERVICE_NAME_MAP.items():
        if keyword in product and mapped_port in SERVICE_SCRIPTS:
            log(f"  [*] Port {port} non-standard — matched product '{product}' to port {mapped_port} scripts")
            return SERVICE_SCRIPTS[mapped_port]

    return None

#  HELPERS
# ══════════════════════════════════════════════════════════
def banner():
    print(f"""
{CYAN}{BOLD}
 ███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ╚══███╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ███╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
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


# ══════════════════════════════════════════════════════════
#  STATE MANAGEMENT (Feature 9 — Resume interrupted scans)
# ══════════════════════════════════════════════════════════
def save_state(output_dir, phase, data=None):
    """Save current scan state to JSON so interrupted scans can resume."""
    state_file = os.path.join(output_dir, ".zrecon_state.json")
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
        except Exception:
            state = {}
    state["last_phase"]  = phase
    state["timestamp"]   = datetime.now().isoformat()
    if data:
        state.update(data)
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)


def load_state(output_dir):
    """Load saved scan state if it exists."""
    state_file = os.path.join(output_dir, ".zrecon_state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                state = json.load(f)
            log(f"Resuming from saved state — last completed phase: {state.get('last_phase', 'unknown')}", "warn")
            return state
        except Exception as e:
            log(f"Could not load state file: {e}", "warn")
    return {}


def clear_state(output_dir):
    """Remove state file after successful scan completion."""
    state_file = os.path.join(output_dir, ".zrecon_state.json")
    if os.path.exists(state_file):
        os.remove(state_file)


# ══════════════════════════════════════════════════════════
#  /etc/hosts MANAGEMENT (Feature 7)
# ══════════════════════════════════════════════════════════
def update_hosts_file(target_ip, hostnames):
    """
    Prompt to add discovered hostnames to /etc/hosts.
    Only adds entries that don't already exist.
    """
    if not hostnames:
        return

    # Filter out already existing entries
    new_hostnames = []
    try:
        with open('/etc/hosts', 'r') as f:
            existing = f.read()
        for hostname in hostnames:
            if hostname not in existing:
                new_hostnames.append(hostname)
    except Exception:
        new_hostnames = hostnames

    if not new_hostnames:
        log("All discovered hostnames already in /etc/hosts")
        return

    log(f"\nDiscovered hostnames not in /etc/hosts:")
    for hostname in new_hostnames:
        log(f"  {target_ip}  {hostname}")

    try:
        confirm = input(f"\nAdd {len(new_hostnames)} hostname(s) to /etc/hosts? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = 'n'

    if confirm == 'y':
        entry = f"{target_ip}  {' '.join(new_hostnames)}  # zrecon"
        try:
            import subprocess as sp
            result = sp.run(
                f"echo '{entry}' | sudo tee -a /etc/hosts",
                shell=True, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                log(f"Added to /etc/hosts: {entry}", "success")
            else:
                log(f"Failed to update /etc/hosts: {result.stderr.strip()}", "error")
        except Exception as e:
            log(f"Could not update /etc/hosts: {e}", "error")
    else:
        log(f"Skipped — manual command:")
        log(f"  echo '{target_ip}  {chr(32).join(new_hostnames)}' | sudo tee -a /etc/hosts")


def save_output(output_dir, filename, content):
    """Save scan output to file."""
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath


def check_target_reachable(target):
    """
    Verify target is reachable before scanning.
    Returns (reachable: bool, message: str)
    """
    import socket
    import subprocess as sp

    def _is_ip(addr):
        try:
            socket.inet_aton(addr.split('/')[0])
            return True
        except socket.error:
            return False

    # Resolve hostname to IP first
    resolved_ip = target
    if not _is_ip(target):
        try:
            resolved_ip = socket.gethostbyname(target)
            log(f"Resolved {target} to {resolved_ip}")
        except socket.gaierror:
            return False, f"Cannot resolve hostname '{target}' — check the target is correct and DNS is working"

    # Validate IP format
    if not _is_ip(resolved_ip):
        return False, f"Invalid IP address format: {target}"

    # Check if target is on local network or routable
    # Skip ping check for subnets — sweep handles that
    if '/' in target:
        return True, "Subnet target — skipping reachability check"

    # Ping check — 3 packets, 2 second timeout
    ping_result = sp.run(
        ["ping", "-c", "3", "-W", "2", resolved_ip],
        capture_output=True,
        text=True
    )

    if ping_result.returncode == 0:
        return True, f"Target {resolved_ip} is reachable"

    # Ping failed — could be firewall blocking ICMP
    # Try TCP connect on common ports before giving up
    common_ports = [22, 80, 443, 445, 3389]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((resolved_ip, port))
            sock.close()
            if result == 0:
                return True, f"Target {resolved_ip} is reachable (port {port}/tcp open)"
        except Exception:
            continue

    # Both ping and TCP failed
    return False, (
        f"Target {resolved_ip} appears unreachable\n"
        f"  Possible causes:\n"
        f"  — Host is down or does not exist\n"
        f"  — VPN not connected (required for HackTheBox/CPTS)\n"
        f"  — Firewall blocking all traffic\n"
        f"  — Wrong IP address\n"
        f"  Tip: Check VPN with 'ip a' and confirm tun0 interface exists"
    )


def run_nmap_subprocess(target, args, output_dir, filename, use_oA=False):
    """
    Run nmap directly via subprocess.
    If use_oA is True also saves .nmap .gnmap .xml formats via -oA.
    Default output is .txt only.
    """
    # Build base command
    cmd = f"nmap {args}"

    # Add -oA if requested
    if use_oA:
        base_name = filename.replace('.txt', '')
        oA_path   = os.path.join(output_dir, base_name)
        cmd += f" -oA {oA_path}"

    cmd += f" {target}"
    log(f"Running: {cmd}")

    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=600   # 10 minute timeout per nmap command
        )
    except subprocess.TimeoutExpired:
        log(f"Nmap command timed out after 10 minutes — {filename}", "error")
        return ""
    except FileNotFoundError:
        log("nmap not found — install with: sudo apt install nmap", "error")
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error running nmap: {e}", "error")
        return ""

    output = result.stdout

    # Check for common nmap errors
    if result.returncode != 0:
        if "Failed to resolve" in result.stderr or "Failed to resolve" in output:
            log(f"Target could not be resolved — check hostname is correct", "error")
        elif "Host seems down" in output:
            log(f"Target appears down — try running with -Pn or check connectivity", "warn")
        elif "Permission denied" in result.stderr:
            log(f"Permission denied — try running with sudo", "error")
        else:
            log(f"Nmap returned non-zero exit code: {result.returncode}", "warn")

    if result.stderr and "WARNING" not in result.stderr:
        output += f"\n[STDERR]\n{result.stderr}"

    # Always save .txt
    filepath = save_output(output_dir, filename, output)
    if use_oA:
        log(f"Saved to: {filepath} + .nmap/.gnmap/.xml", "success")
    else:
        log(f"Saved to: {filepath}", "success")
    return output


# ══════════════════════════════════════════════════════════
#  PHASE 1 — PORT DISCOVERY
# ══════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════
#  PHASE 0 — DNS ENUMERATION
# ══════════════════════════════════════════════════════════
def phase0_dns_enumeration(target, output_dir, domain=None):
    """
    Dedicated DNS enumeration phase — runs before port scanning.
    Attempts standard record lookups, zone transfer via dig,
    and tries all discovered nameservers for AXFR.
    Returns (results dict, discovered_domain string).
    Prompts user to add discovered domain to /etc/hosts.
    """
    import subprocess as sp

    log("PHASE 0 — DNS Enumeration", "section")

    def _is_ip(addr):
        import socket
        try:
            socket.inet_aton(addr.split("/")[0])
            return True
        except socket.error:
            return False

    # Derive domain if not provided
    if not domain:
        if not _is_ip(target):
            # Target is already a hostname — extract domain
            parts = target.rstrip(".").split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else target
            log(f"Derived domain from target: {domain}")
        else:
            # Step 1 — Try reverse DNS
            log("No domain provided — attempting reverse DNS lookup...")
            try:
                rev = sp.run(
                    ["dig", "-x", target, "+short"],
                    capture_output=True, text=True, timeout=10
                )
                hostname = rev.stdout.strip().rstrip(".")
                if hostname:
                    parts = hostname.split(".")
                    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
                    log(f"Derived domain from reverse DNS: {domain}")
                else:
                    log("Reverse DNS returned no result", "warn")
            except Exception as e:
                log(f"Reverse DNS failed: {e}", "warn")

            # Step 2 — Query target DNS server directly for SOA/NS records
            if not domain:
                log(f"Querying target DNS server {target} directly...")
                discovered = None

                # Try SOA on common internal TLDs
                common_tlds = ["local", "lan", "internal", "corp", "htb", "inlanefreight.local"]
                for tld in common_tlds:
                    try:
                        result = sp.run(
                            ["dig", "SOA", tld, f"@{target}", "+short", "+time=3", "+tries=1"],
                            capture_output=True, text=True, timeout=8
                        )
                        if result.stdout.strip():
                            discovered = tld
                            log(f"Found domain via SOA query: {tld}", "success")
                            break
                    except Exception:
                        continue

                # Try NS record for root
                if not discovered:
                    try:
                        result = sp.run(
                            ["dig", "NS", ".", f"@{target}", "+short", "+time=3", "+tries=1"],
                            capture_output=True, text=True, timeout=8
                        )
                        if result.stdout.strip():
                            for line in result.stdout.strip().split("\n"):
                                ns = line.strip().rstrip(".")
                                if ns and "." in ns:
                                    parts = ns.split(".")
                                    discovered = ".".join(parts[-2:])
                                    log(f"Found domain via NS root query: {discovered}", "success")
                                    break
                    except Exception:
                        pass

                # Try version.bind and hostname.bind
                if not discovered:
                    for query in ["hostname.bind", "version.bind"]:
                        try:
                            result = sp.run(
                                ["dig", "TXT", query, "CHAOS", f"@{target}", "+short"],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.stdout.strip():
                                log(f"DNS server info: {result.stdout.strip()}")
                        except Exception:
                            pass

                if discovered:
                    domain = discovered
                else:
                    # Step 3 — Prompt user
                    log("Could not auto-discover domain from DNS server", "warn")
                    try:
                        user_input = input(f"\n[?] Enter domain name for DNS enumeration (e.g. inlanefreight.local) or press Enter to skip: ").strip()
                        if user_input:
                            domain = user_input
                            log(f"Domain set to: {domain}", "success")
                        else:
                            log("No domain provided — skipping DNS enumeration", "warn")
                            return {}, None
                    except (EOFError, KeyboardInterrupt):
                        log("Skipping DNS enumeration", "warn")
                        return {}, None

    log(f"Target:  {target}")
    log(f"Domain:  {domain}")

    results  = {}
    dns_log  = []

    # ── Standard record enumeration ──────────────────────
    log("\nEnumerating DNS records...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    for rtype in record_types:
        try:
            cmd = ["dig", rtype, domain, f"@{target}", "+noall", "+answer"]
            result = sp.run(cmd, capture_output=True, text=True, timeout=10)
            if result.stdout.strip():
                results[rtype] = result.stdout.strip()
                dns_log.append(f"[{rtype}]\n{result.stdout.strip()}\n")
                for line in result.stdout.strip().split("\n"):
                    log(f"  [{rtype}] {line}", "success")
            else:
                log(f"  [{rtype}] No records found")
        except sp.TimeoutExpired:
            log(f"  [{rtype}] Timed out", "warn")
        except Exception as e:
            log(f"  [{rtype}] Error: {e}", "warn")

    # ── Collect nameservers for AXFR attempts ─────────────
    nameservers = [target]  # Always try the target first

    if "NS" in results:
        for line in results["NS"].split("\n"):
            parts = line.split()
            if parts:
                ns = parts[-1].rstrip(".")
                if ns and ns not in nameservers:
                    nameservers.append(ns)
                    log(f"  Found nameserver: {ns}")

    # ── Zone transfer attempts ────────────────────────────
    log(f"\nAttempting zone transfer (AXFR) for {domain}...")
    axfr_success = False

    for ns in nameservers:
        log(f"  Trying AXFR via {ns}...")
        try:
            axfr = sp.run(
                ["dig", "axfr", domain, f"@{ns}"],
                capture_output=True, text=True, timeout=30
            )

            output = axfr.stdout

            if "XFR size" in output:
                log(f"ZONE TRANSFER SUCCESSFUL via {ns}", "success")
                log("All DNS records exposed:", "success")
                print(f"\n{output}")

                results[f"axfr_{ns}"] = output
                dns_log.append(f"[AXFR via {ns} — SUCCESS]\n{output}\n")

                safe_ns = ns.replace(".", "_")
                save_output(output_dir, f"00_dns_axfr_{safe_ns}.txt", output)
                axfr_success = True

            elif "Transfer failed" in output or "REFUSED" in output:
                log(f"  Zone transfer refused by {ns}", "warn")
                dns_log.append(f"[AXFR via {ns} — REFUSED]\n")

            elif "connection timed out" in output or not output.strip():
                log(f"  Zone transfer timed out via {ns}", "warn")

            else:
                log(f"  Zone transfer returned no records via {ns}", "warn")
                dns_log.append(f"[AXFR via {ns} — NO RECORDS]\n{output}\n")

        except sp.TimeoutExpired:
            log(f"  Zone transfer timed out via {ns}", "warn")
        except Exception as e:
            log(f"  Zone transfer error via {ns}: {e}", "warn")

    if not axfr_success:
        log("Zone transfer failed on all nameservers — server is properly configured", "warn")

    # ── Subdomain brute force hint ────────────────────────
    log(f"\n[TIP] Run subdomain brute force manually for deeper coverage:")
    log(f"      dnsrecon -d {domain} -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    log(f"      dnsx -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -a -resp")

    # ── Save all results ──────────────────────────────────
    full_output = f"DNS Enumeration — {domain}\n"
    full_output += f"Target: {target}\n"
    full_output += f"{'='*60}\n\n"
    full_output += "\n".join(dns_log)

    save_output(output_dir, "00_dns_enum.txt", full_output)
    log(f"\nDNS enumeration complete — saved to 00_dns_enum.txt", "success")

    # Prompt to add discovered domain to /etc/hosts
    if domain:
        update_hosts_file(target, [domain])

    return results, domain


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
            arguments="-Pn -p- --min-rate 5000 --open"
        )
    except Exception as e:
        log(f"Port discovery error: {e}", "error")
        log("Check that the target is reachable and nmap is installed", "error")
        return []

    open_ports = []

    for host in nm.all_hosts():
        state = nm[host].state()
        if state == 'down':
            log(f"Host {host} appears to be down", "warn")
            log("If the host is up but blocking ping try: python3 zrecon.py -t TARGET (nmap uses -Pn by default)", "warn")
            continue
        log(f"Host: {host} ({state})", "success")
        if 'tcp' in nm[host]:
            for port, data in nm[host]['tcp'].items():
                if data['state'] == 'open':
                    open_ports.append(port)
                    log(f"  Port {port}/tcp OPEN", "success")

    if not open_ports:
        log("No open TCP ports found", "warn")
        log("Possible reasons:", "warn")
        log("  — Host is down or unreachable", "warn")
        log("  — All ports are filtered by a firewall", "warn")
        log("  — VPN not connected (HackTheBox requires tun0)", "warn")
        log("  — Wrong target IP", "warn")

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
        filename="02_service_detection.txt",
                use_oA=USE_OA
    )

    # Parse services from nmap output directly — no second scan
    services = {}
    current_port = None
    for line in output.split('\n'):
        # Match port lines: "80/tcp   open  http    Apache httpd 2.4.41"
        import re
        port_match = re.match(r'^(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)', line)
        if port_match:
            port_num  = int(port_match.group(1))
            state     = port_match.group(2)
            svc_name  = port_match.group(3)
            version   = port_match.group(4).strip()
            # Split version into product + version
            parts = version.split(' ', 1)
            product = parts[0] if parts else ''
            ver     = parts[1] if len(parts) > 1 else ''
            services[port_num] = {
                "name":    svc_name,
                "product": product,
                "version": ver,
                "state":   state
            }
            log(f"  {port_num}/tcp — {svc_name} {version}".strip(), "success")

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
        filename="03_udp_scan.txt",
                use_oA=USE_OA
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
# ══════════════════════════════════════════════════════════
#  SSH DEFAULT CREDENTIAL CHECK
# ══════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════
#  SMTP USER ENUMERATION
# ══════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════
#  RPCINFO EXECUTION
# ══════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════
#  SMB NULL SESSION / GUEST ENUMERATION
# ══════════════════════════════════════════════════════════
def check_smb_null_session(target, port, output_dir):
    """
    Try SMB null session and guest login to enumerate shares.
    Uses smbclient and crackmapexec if available.
    """
    import subprocess as sp
    import shutil

    log(f"\n[Port {port}] Checking SMB null session and guest access...")

    results = []

    # ── smbclient share listing ───────────────────────────
    if shutil.which("smbclient"):
        for user, label in [("", "null session"), ("guest", "guest")]:
            try:
                cmd = ["smbclient", "-L", f"//{target}", "-N"] if not user else                       ["smbclient", "-L", f"//{target}", "-U", "guest%"]
                result = sp.run(cmd, capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr

                if "Sharename" in output or "ADMIN$" in output or "IPC$" in output:
                    log(f"  [✓] smbclient {label} — shares found:", "success")
                    for line in output.split("\n"):
                        if line.strip() and not line.startswith("session") and not line.startswith("Reconnecting"):
                            log(f"      {line}")
                    results.append(f"smbclient {label}: {output}")
                elif "NT_STATUS_ACCESS_DENIED" in output:
                    log(f"  [-] smbclient {label} — access denied")
                elif "NT_STATUS_LOGON_FAILURE" in output:
                    log(f"  [-] smbclient {label} — login failed")
                else:
                    log(f"  [-] smbclient {label} — no shares")

            except sp.TimeoutExpired:
                log(f"  smbclient {label} timed out", "warn")
            except Exception as e:
                log(f"  smbclient error: {e}", "warn")
    else:
        log("  smbclient not found — install with: sudo apt install smbclient", "warn")

    if results:
        # Save output
        save_output(output_dir, f"04_{port}_smb_null.txt", "\n".join(results))
        log(f"  Saved to: 04_{port}_smb_null.txt", "success")

    return results


# ══════════════════════════════════════════════════════════
#  LDAP ANONYMOUS BIND ENUMERATION
# ══════════════════════════════════════════════════════════
def check_ldap_anonymous(target, port, output_dir, domain=None):
    """
    Attempt LDAP anonymous bind to enumerate directory info.
    Tries to extract naming contexts and base DN entries.
    """
    import subprocess as sp
    import shutil

    log(f"\n[Port {port}] Attempting LDAP anonymous bind...")

    if not shutil.which("ldapsearch"):
        log("  ldapsearch not found — install with: sudo apt install ldap-utils", "warn")
        log(f"  Manual: ldapsearch -x -H ldap://{target} -b '' -s base namingContexts", "warn")
        return []

    proto  = "ldaps" if port in [636, 3269] else "ldap"
    uri    = f"{proto}://{target}:{port}"
    results = []

    # ── Step 1: Get naming contexts ───────────────────────
    log(f"  Getting naming contexts from {uri}...")
    try:
        result = sp.run(
            ["ldapsearch", "-x", "-H", uri, "-b", "", "-s", "base", "namingContexts"],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout

        naming_contexts = []
        for line in output.split("\n"):
            if "namingContexts:" in line:
                nc = line.split("namingContexts:")[-1].strip()
                naming_contexts.append(nc)
                log(f"  [✓] Naming context: {nc}", "success")

        results.append(f"[Naming Contexts]\n{output}")

        if not naming_contexts and domain:
            # Derive base DN from domain
            parts = domain.split(".")
            naming_contexts = ["dc=" + ",dc=".join(parts)]
            log(f"  Derived base DN: {naming_contexts[0]}")

    except sp.TimeoutExpired:
        log(f"  LDAP naming context lookup timed out", "warn")
        return []
    except Exception as e:
        log(f"  LDAP error: {e}", "warn")
        return []

    # ── Step 2: Enumerate base DN ─────────────────────────
    for base_dn in naming_contexts:
        log(f"  Enumerating base DN: {base_dn}...")
        try:
            result = sp.run(
                ["ldapsearch", "-x", "-H", uri, "-b", base_dn],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            if "result: 0 Success" in output or "numEntries" in output:
                # Count entries
                entries = output.count("dn:")
                log(f"  [✓] Anonymous bind successful — {entries} entries found", "success")
                results.append(f"[Base DN: {base_dn}]\n{output}")

                # Extract useful info
                users     = [l.split(":")[-1].strip() for l in output.split("\n") if "sAMAccountName:" in l]
                groups    = [l.split(":")[-1].strip() for l in output.split("\n") if "cn:" in l and "group" in l.lower()]
                desc      = [l.split(":")[-1].strip() for l in output.split("\n") if "description:" in l]

                if users:
                    log(f"  [!] Users found: {users}", "warn")
                if groups:
                    log(f"  [!] Groups found: {groups[:5]}", "warn")
                if desc:
                    log(f"  [!] Descriptions (may contain passwords): {desc[:3]}", "warn")

                # Save full output
                save_output(output_dir, f"04_{port}_ldap_anonymous.txt", "\n".join(results))
                log(f"  Saved to: 04_{port}_ldap_anonymous.txt", "success")

            elif "Insufficient access" in output or "result: 50" in output:
                log(f"  [-] Anonymous bind refused — server requires authentication")
            elif "result: 32" in output:
                log(f"  [-] Base DN not found: {base_dn}")
            else:
                log(f"  [-] No results for {base_dn}")

        except sp.TimeoutExpired:
            log(f"  LDAP enumeration timed out for {base_dn}", "warn")
        except Exception as e:
            log(f"  LDAP enumeration error: {e}", "warn")

    return results


def run_rpcinfo(target, port, output_dir):
    """
    Run rpcinfo binary against target when RPC port 111 is found.
    Reveals registered RPC services — NFS, NIS, mountd etc.
    """
    import subprocess as sp
    import shutil

    log(f"\n[Port {port}] Running rpcinfo against {target}...")

    # Check rpcinfo is installed
    if not shutil.which("rpcinfo"):
        log("  rpcinfo not found — install with: sudo apt install rpcbind", "warn")
        log(f"  Manual check: rpcinfo -p {target}", "warn")
        return

    try:
        result = sp.run(
            ["rpcinfo", "-p", target],
            capture_output=True, text=True, timeout=30
        )

        output = result.stdout

        if result.returncode != 0 or not output.strip():
            log(f"  rpcinfo returned no results — host may be filtering port {port}", "warn")
            if result.stderr:
                log(f"  Error: {result.stderr.strip()}", "warn")
            return

        # Display output
        log(f"  rpcinfo output:", "success")
        for line in output.strip().split("\n"):
            log(f"    {line}")

        # Save to file
        save_output(output_dir, f"04_{port}_rpcinfo.txt", output)
        log(f"  Saved to: 04_{port}_rpcinfo.txt", "success")

        # Flag interesting services
        interesting = ["nfs", "mountd", "nlockmgr", "nis", "yp", "portmapper"]
        found_services = []
        for line in output.lower().split("\n"):
            for svc in interesting:
                if svc in line and svc not in found_services:
                    found_services.append(svc)

        if "nfs" in found_services or "mountd" in found_services:
            log(f"\n  [!] NFS/mountd detected — check for accessible shares:", "warn")
            log(f"      showmount -e {target}")
            log(f"      mount -t nfs {target}:/SHARE /mnt/nfs -o nolock")

        if "nis" in found_services or "yp" in found_services:
            log(f"\n  [!] NIS/YP detected — may expose user/password maps:", "warn")
            log(f"      ypwhich -d DOMAIN")
            log(f"      ypcat -d DOMAIN passwd.byname")

    except sp.TimeoutExpired:
        log(f"  rpcinfo timed out after 30 seconds", "warn")
    except Exception as e:
        log(f"  rpcinfo error: {e}", "error")


def check_smtp_users(target, port=25):
    """
    Enumerate valid SMTP users via VRFY command.
    A 252 response = user exists.
    A 550 response = user does not exist.
    """
    import socket

    COMMON_USERS = [
        "root", "admin", "administrator", "www-data",
        "mail", "postmaster", "daemon", "ftp",
        "nobody", "info", "test", "guest",
        "user", "ubuntu", "apache", "mysql",
        "support", "helpdesk", "sales", "contact",
        "webmaster", "hostmaster", "abuse",
        "noreply", "no-reply", "office",
    ]

    log(f"\n[Port {port}] Enumerating SMTP users via VRFY...")

    valid_users = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))

        # Read banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        log(f"  Banner: {banner}")

        # Send EHLO
        sock.send(b"EHLO zrecon\r\n")
        sock.recv(1024)

        # Try VRFY for each user
        for user in COMMON_USERS:
            try:
                sock.send(f"VRFY {user}\r\n".encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                # 252 = user exists (cannot verify but will accept)
                # 250 = user exists and verified
                # 550 = user does not exist
                # 551, 553 = user does not exist
                if response.startswith("252") or response.startswith("250"):
                    log(f"  [VALID USER] {user} — {response}", "success")
                    valid_users.append(user)
                elif response.startswith("550") or response.startswith("551") or response.startswith("553"):
                    log(f"  [-] {user} — not found")
                elif response.startswith("502") or response.startswith("500"):
                    log(f"  VRFY command disabled on this server", "warn")
                    break
                else:
                    log(f"  [?] {user} — {response}")

            except socket.timeout:
                log(f"  Timeout on user {user}", "warn")
                break
            except Exception as e:
                log(f"  Error checking {user}: {e}", "warn")
                break

        # Send QUIT
        try:
            sock.send(b"QUIT\r\n")
        except Exception:
            pass
        sock.close()

    except ConnectionRefusedError:
        log(f"  SMTP port {port} connection refused on {target}", "error")
        return []
    except socket.timeout:
        log(f"  Connection to {target}:{port} timed out", "error")
        return []
    except Exception as e:
        log(f"  SMTP enum error: {e}", "error")
        return []

    if valid_users:
        log(f"\n  [!] Found {len(valid_users)} valid SMTP user(s): {valid_users}", "warn")
        log(f"  [TIP] Use valid users for password spraying:")
        log(f"      hydra -L valid_users.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt {target} ssh")
    else:
        log(f"  No valid users found or VRFY disabled")

    return valid_users


def check_ssh_default_creds(target, port=22):
    """
    Try a small set of common default SSH credentials.
    Uses paramiko if available, falls back to tip-only if not.
    Not a brute force — just quick sanity check for weak creds.
    """
    DEFAULT_CREDS = [
        ("admin",    "admin"),
        ("root",     "toor"),
        ("admin",    "Welcome"),
        ("admin",    "Pass123"),
        ("root",     "root"),
        ("admin",    "password"),
        ("root",     "password"),
        ("admin",    "admin123"),
        ("user",     "user"),
        ("ubuntu",   "ubuntu"),
        ("guest",    "guest"),
    ]

    log(f"\n[Port {port}] Checking default SSH credentials...")

    try:
        import paramiko
    except ImportError:
        log("  paramiko not installed — skipping SSH credential check", "warn")
        log("  Install with: pip install paramiko", "warn")
        return []

    found = []

    for username, password in DEFAULT_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=5,
                banner_timeout=5,
                auth_timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            # Login succeeded
            log(f"  [VALID CREDS] {username}:{password}", "warn")
            found.append((username, password))
            client.close()

        except paramiko.AuthenticationException:
            # Wrong password — expected
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            log(f"  SSH port {port} not reachable on {target}", "error")
            break
        except Exception as e:
            err = str(e).lower()
            if "connection refused" in err:
                log(f"  Connection refused on port {port}", "error")
                break
            elif "timed out" in err or "timeout" in err:
                log(f"  Connection timed out — skipping remaining checks", "warn")
                break
            else:
                # Auth method not supported etc — skip silently
                pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    if found:
        log(f"  [!] {len(found)} default credential(s) worked:", "warn")
        for user, passwd in found:
            log(f"      ssh {user}@{target} (password: {passwd})", "warn")
    else:
        log(f"  No default credentials worked on port {port}")

    return found


def post_scan_tips(port, svc_name, target):
    """
    Print actionable next step tips after each service is scanned.
    Reminds operator of manual follow-up steps the script can't automate.
    """
    tips = {
        # IMAP
        "IMAP": [
            f"{YELLOW}[TIP] IMAP found — if on a Linux host try Evolution mail client:{RESET}",
            f"      sudo apt install evolution",
            f"      Launch Evolution → New Account → IMAP",
            f"      Server: {target}  Port: 143  SSL: None/STARTTLS",
            f"      Use any credentials found during enumeration",
            f"      Evolution lets you browse mailboxes interactively",
        ],
        "IMAPS": [
            f"{YELLOW}[TIP] IMAPS found — try Evolution mail client:{RESET}",
            f"      sudo apt install evolution",
            f"      Launch Evolution → New Account → IMAP",
            f"      Server: {target}  Port: 993  SSL: SSL/TLS",
            f"      Use any credentials found during enumeration",
        ],
        # POP3
        "POP3": [
            f"{YELLOW}[TIP] POP3 found — manually check with telnet or Evolution:{RESET}",
            f"      telnet {target} 110",
            f"      USER username",
            f"      PASS password",
            f"      LIST         (list messages)",
            f"      RETR 1       (retrieve message 1)",
            f"      Or use Evolution: New Account → POP  Port: 110",
        ],
        "POP3S": [
            f"{YELLOW}[TIP] POP3S found — try Evolution:{RESET}",
            f"      Evolution → New Account → POP  Port: 995  SSL: SSL/TLS",
        ],
        # FTP
        "FTP": [
            f"{YELLOW}[TIP] FTP found — check anonymous login and download all files:{RESET}",
            f"      ftp {target}",
            f"      Username: anonymous  Password: (blank or any email)",
            f"      If logged in: wget -m ftp://anonymous:@{target}/",
            f"      Also check binary mode for non-text files: binary",
        ],
        # SMB
        "SMB": [
            f"{YELLOW}[TIP] SMB found — enumerate shares and check access:{RESET}",
            f"      smbclient -L //{target} -N",
            f"      smbclient //{target}/SHARENAME -N",
            f"      crackmapexec smb {target} -u '' -p '' --shares",
            f"      crackmapexec smb {target} -u 'guest' -p '' --shares",
        ],
        # SMTP
        "SMTP": [
            f"{YELLOW}[TIP] SMTP found — enumerate users manually:{RESET}",
            f"      nc {target} 25",
            f"      EHLO test",
            f"      VRFY root",
            f"      VRFY admin",
            f"      smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {target}",
        ],
        # DNS
        "DNS": [
            f"{YELLOW}[TIP] DNS found — attempt zone transfer manually:{RESET}",
            f"      dig axfr @{target} DOMAIN.local",
            f"      dnsrecon -d DOMAIN.local -a -n {target}",
            f"      Add discovered hostnames to /etc/hosts",
        ],
        # NFS/RPC
        "RPC": [
            f"{YELLOW}[TIP] RPC found — check for NFS shares:{RESET}",
            f"      showmount -e {target}",
            f"      mount -t nfs {target}:/SHARE /mnt/nfs -o nolock",
            f"      ls -la /mnt/nfs",
        ],
        "NFS": [
            f"{YELLOW}[TIP] NFS found — mount and explore shares:{RESET}",
            f"      showmount -e {target}",
            f"      mkdir /mnt/nfs",
            f"      mount -t nfs {target}:/SHARE /mnt/nfs -o nolock",
            f"      ls -la /mnt/nfs",
            f"      Check for .ssh keys, config files, backups",
        ],
        # HTTP
        "HTTP": [
            f"{YELLOW}[TIP] HTTP found — enumerate further:{RESET}",
            f"      ffuf -u http://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403",
            f"      Check page source for comments and hidden fields",
            f"      Check /robots.txt and /sitemap.xml manually",
            f"      Add {target} to /etc/hosts if hostname based vhosts suspected",
        ],
        "HTTPS": [
            f"{YELLOW}[TIP] HTTPS found — check SSL cert for hostnames:{RESET}",
            f"      openssl s_client -connect {target}:443 | openssl x509 -noout -text | grep DNS",
            f"      Add any discovered hostnames to /etc/hosts",
            f"      ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403",
        ],
        # SNMP
        "SNMP": [
            f"{YELLOW}[TIP] SNMP found — try common community strings:{RESET}",
            f"      snmpwalk -v2c -c public {target}",
            f"      snmpwalk -v2c -c private {target}",
            f"      onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {target}",
            f"      # If valid string found — full walk:",
            f"      snmpwalk -v2c -c COMMUNITY {target}",
            f"      snmpwalk -v2c -c COMMUNITY {target} 1.3.6.1.2.1.25.4.2.1.2  (running processes)",
            f"      snmpwalk -v2c -c COMMUNITY {target} 1.3.6.1.2.1.25.6.3.1.2  (installed software)",
        ],
        # MySQL
        "MySQL": [
            f"{YELLOW}[TIP] MySQL found — try connecting:{RESET}",
            f"      mysql -h {target} -u root",
            f"      mysql -h {target} -u root -p",
            f"      show databases;",
            f"      select user,password from mysql.user;",
        ],
        # MSSQL
        "MSSQL": [
            f"{YELLOW}[TIP] MSSQL found — try connecting:{RESET}",
            f"      impacket-mssqlclient sa@{target}",
            f"      impacket-mssqlclient DOMAIN/user:pass@{target} -windows-auth",
            f"      enable_xp_cmdshell",
            f"      xp_cmdshell whoami",
        ],
        # RDP
        "RDP": [
            f"{YELLOW}[TIP] RDP found — try connecting with found credentials:{RESET}",
            f"      xfreerdp /u:USERNAME /p:PASSWORD /v:{target}",
            f"      rdesktop {target}",
        ],
        # Redis
        "Redis": [
            f"{YELLOW}[TIP] Redis found — check for unauthenticated access:{RESET}",
            f"      redis-cli -h {target}",
            f"      INFO",
            f"      KEYS *",
            f"      Check for webshell upload via redis config set",
        ],
        # VNC
        "VNC": [
            f"{YELLOW}[TIP] VNC found — try connecting:{RESET}",
            f"      vncviewer {target}",
            f"      Try empty password or common passwords",
        ],
        # LDAP
        "LDAP": [
            f"{YELLOW}[TIP] LDAP found — enumerate anonymously:{RESET}",
            f"      ldapsearch -x -H ldap://{target} -b 'dc=DOMAIN,dc=local'",
            f"      ldapsearch -x -H ldap://{target} -b '' -s base namingContexts",
            f"      bloodhound-python -u user -p pass -d DOMAIN.local -ns {target} -c all",
        ],
        # distcc
        "distcc": [
            f"{YELLOW}[TIP] distcc found — likely vulnerable to RCE (CVE-2004-2687):{RESET}",
            f"      nmap -Pn --script distcc-cve2004-2687 -p 3632 {target}",
            f"      Use metasploit: use exploit/unix/misc/distcc_exec",
        ],
        # JDWP
        "JDWP": [
            f"{YELLOW}[TIP] JDWP (Java Debug) found — likely RCE:{RESET}",
            f"      nmap -Pn --script jdwp-exec --script-args cmd='id' -p 5005 {target}",
            f"      Use exploit: https://github.com/IOActive/jdwp-shellifier",
        ],
        # WinRM
        "WinRM-HTTP": [
            f"{YELLOW}[TIP] WinRM found — try connecting with found credentials:{RESET}",
            f"      evil-winrm -i {target} -u USERNAME -p PASSWORD",
            f"      evil-winrm -i {target} -u USERNAME -H NTLMHASH",
        ],
        # IPMI
        "IPMI": [
            f"{YELLOW}[TIP] IPMI found — check for cipher zero auth bypass:{RESET}",
            f"      ipmitool -I lanplus -H {target} -U admin -P '' user list",
            f"      Use metasploit: use auxiliary/scanner/ipmi/ipmi_dumphashes",
            f"      Cipher zero vulnerability gives plaintext credentials",
        ],
    }

    svc_tips = tips.get(svc_name)
    if svc_tips:
        print()
        for tip in svc_tips:
            print(f"  {tip}")
        print()


def phase4_script_enumeration(target, open_ports, output_dir, services=None):
    """
    Run all NSE scripts in a single nmap command instead of
    one per port — dramatically faster than sequential calls.
    Scripts are selected per port then deduplicated and combined.
    UDP ports run separately since they need -sU flag.
    """
    log("PHASE 4 — Targeted NSE Script Enumeration", "section")

    if services is None:
        services = {}

    results      = {}
    tcp_scripts  = set()
    udp_scripts  = set()
    tcp_ports    = []
    udp_ports    = []
    unmapped     = []
    port_svc_map = {}

    # ── Build combined script sets ───────────────────────
    for port in open_ports:
        svc_config = get_scripts_for_port(port, services)

        if svc_config:
            port_svc_map[port] = svc_config
            scripts = [s.strip() for s in svc_config["scripts"].split(",")]

            if "-sU" in svc_config.get("extra_args", ""):
                udp_scripts.update(scripts)
                udp_ports.append(port)
            else:
                tcp_scripts.update(scripts)
                tcp_ports.append(port)
        else:
            unmapped.append(port)

    # ── Run one TCP script command for all ports ─────────
    if tcp_ports and tcp_scripts:
        ports_str   = ",".join([str(p) for p in tcp_ports])
        scripts_str = ",".join(sorted(tcp_scripts))

        log(f"Running {len(tcp_scripts)} scripts against {len(tcp_ports)} TCP ports in one pass...")

        output = run_nmap_subprocess(
            target=target,
            args=f"-Pn --script {scripts_str} -p {ports_str}",
            output_dir=output_dir,
            filename="04_tcp_scripts.txt",
            use_oA=USE_OA
        )

        # Store output for each port
        for port in tcp_ports:
            svc_config = port_svc_map.get(port, {})
            svc_name   = svc_config.get("name", "unknown")
            results[port] = {
                "service": svc_name,
                "scripts": svc_config.get("scripts", ""),
                "output":  output
            }

        # Highlight interesting findings ONCE — not per port
        log("\nInteresting findings:")
        seen = set()
        for line in output.split('\n'):
            if line.strip() in seen:
                continue
            seen.add(line.strip())
            if "@openssh.com" in line:
                weak_algos = ["arcfour", "blowfish-cbc", "3des-cbc",
                              "diffie-hellman-group1-sha1",
                              "diffie-hellman-group14-sha1",
                              "hmac-md5", "ssh-dss"]
                if any(w in line for w in weak_algos):
                    log(f"  [WEAK ALGO] {line.strip()}", "warn")
                continue
            if "NOT VULNERABLE" in line or "not vulnerable" in line:
                continue
            weak_standalone = ["hmac-md5", "ssh-dss", "arcfour", "blowfish-cbc", "3des-cbc"]
            if any(w in line for w in weak_standalone):
                log(f"  [WEAK ALGO] {line.strip()}", "warn")
            # Skip port header lines e.g. "21/tcp  open  ftp"
            if line.strip() and line[0].isdigit() and "/tcp" in line:
                continue
            keywords = [
                "VULNERABLE", "vulnerable", "CVE-",
                "Anonymous FTP", "anonymous login",
                "login allowed",
                "password:", "credential",
                "root:", "uid=", "id=",
                "No auth", "WRITABLE", "READ/WRITE",
            ]
            if any(kw in line for kw in keywords):
                log(f"  [INTERESTING] {line.strip()}", "warn")

        # Post-scan tips for all TCP services
        for port in tcp_ports:
            svc_name = port_svc_map.get(port, {}).get("name", "")
            post_scan_tips(port, svc_name, target)

        # ── Active checks — run concurrently ─────────────
        active_tasks = []
        for port in tcp_ports:
            svc_name = port_svc_map.get(port, {}).get("name", "")
            if svc_name == "SSH" or port == 22:
                active_tasks.append(("ssh_creds",  port, svc_name))
            if svc_name == "SMTP" or port in [25, 465, 587]:
                active_tasks.append(("smtp_vrfy",  port, svc_name))
            if svc_name in ["RPC", "rpcbind"] or port == 111:
                active_tasks.append(("rpcinfo",    port, svc_name))
            if svc_name in ["SMB", "SMB-NetBIOS", "microsoft-ds", "netbios-ssn"] or port in [139, 445]:
                active_tasks.append(("smb_null",   port, svc_name))
            if svc_name in ["LDAP", "LDAPS", "Global-Catalog", "Global-Catalog-SSL"] or port in [389, 636, 3268, 3269]:
                active_tasks.append(("ldap_anon",  port, svc_name))

        if active_tasks:
            log(f"\nRunning {len(active_tasks)} active check(s) concurrently...")
            with ThreadPoolExecutor(max_workers=max(len(active_tasks), 1)) as executor:
                futures = []
                for task_type, port, svc_name in active_tasks:
                    if task_type == "ssh_creds":
                        futures.append(executor.submit(check_ssh_default_creds, target, port))
                    elif task_type == "smtp_vrfy":
                        futures.append(executor.submit(check_smtp_users, target, port))
                    elif task_type == "rpcinfo":
                        futures.append(executor.submit(run_rpcinfo, target, port, output_dir))
                    elif task_type == "smb_null":
                        futures.append(executor.submit(check_smb_null_session, target, port, output_dir))
                    elif task_type == "ldap_anon":
                        futures.append(executor.submit(check_ldap_anonymous, target, port, output_dir, args.domain))

                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        log(f"Active check error: {e}", "warn")

    # ── Run UDP scripts separately ────────────────────────
    if udp_ports and udp_scripts:
        ports_str   = ",".join([str(p) for p in udp_ports])
        scripts_str = ",".join(sorted(udp_scripts))

        log(f"Running {len(udp_scripts)} scripts against {len(udp_ports)} UDP ports...")

        output = run_nmap_subprocess(
            target=target,
            args=f"-Pn -sU --script {scripts_str} -p {ports_str}",
            output_dir=output_dir,
            filename="04_udp_scripts.txt",
            use_oA=USE_OA
        )

        for port in udp_ports:
            svc_config = port_svc_map.get(port, {})
            svc_name   = svc_config.get("name", "unknown")
            results[port] = {
                "service": svc_name,
                "scripts": svc_config.get("scripts", ""),
                "output":  output
            }

    # ── Handle unmapped ports with default scripts ────────
    if unmapped:
        ports_str = ",".join([str(p) for p in unmapped])
        log(f"Running default scripts on unmapped ports: {ports_str}")
        output = run_nmap_subprocess(
            target=target,
            args=f"-Pn -sCV --script default -p {ports_str}",
            output_dir=output_dir,
            filename="04_unmapped_default.txt",
            use_oA=USE_OA
        )
        for port in unmapped:
            results[port] = {
                "service": "unknown",
                "scripts": "default",
                "output":  output
            }

    log(f"\nScript enumeration complete — {len(results)} ports scanned", "success")
    return results

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
        filename="05_vuln_scan.txt",
                use_oA=USE_OA
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
        filename="00_host_sweep.txt",
                use_oA=USE_OA
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
# ══════════════════════════════════════════════════════════
#  PHASE 6 — VHOST DISCOVERY
# ══════════════════════════════════════════════════════════
def phase6_vhost_discovery(target, output_dir, domain, ports=None, custom_wordlist=None):
    """
    Virtual host discovery using ffuf.
    Uses Content-Length of an invalid vhost as baseline filter
    to find valid vhosts returning different response sizes.
    Requires ffuf to be installed and --domain to be set.
    """
    import subprocess as sp
    import shutil

    log("PHASE 6 — Vhost Discovery", "section")

    # Check ffuf is installed
    if not shutil.which("ffuf"):
        log("ffuf not found — install with: sudo apt install ffuf", "error")
        log("Or download from: https://github.com/ffuf/ffuf/releases", "error")
        log("Skipping vhost discovery", "warn")
        return {}

    if not domain:
        log("No domain set — use --domain DOMAIN.local to enable vhost discovery", "warn")
        return {}

    # Check wordlist exists
    if custom_wordlist:
        if os.path.exists(custom_wordlist):
            wordlist = custom_wordlist
            log(f"Using custom wordlist: {wordlist}")
        else:
            log(f"Custom wordlist not found: {custom_wordlist}", "error")
            log("Skipping vhost discovery", "warn")
            return {}
    else:
        default_wordlists = [
            "/usr/share/seclists/Discovery/DNS/namelist.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt",
            "/opt/useful/SecLists/Discovery/DNS/namelist.txt",
        ]
        wordlist = None
        for wl in default_wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break

        if not wordlist:
            log("No wordlist found — checked:", "error")
            for wl in default_wordlists:
                log(f"  {wl}", "error")
            log("Install seclists: sudo apt install seclists", "error")
            log("Or specify a custom wordlist: --vhost-wordlist /path/to/wordlist.txt", "error")
            log("Skipping vhost discovery", "warn")
            return {}

    log(f"Target:    {target}")
    log(f"Domain:    {domain}")
    log(f"Wordlist:  {wordlist}")

    # Determine which HTTP ports to check
    http_ports = ports if ports else [80, 443, 8080, 8443]
    results = {}

    for port in http_ports:
        proto = "https" if port in [443, 8443] else "http"
        url   = f"{proto}://{target}:{port}/" if port not in [80, 443] else f"{proto}://{target}/"

        log(f"\n[Port {port}] Checking vhosts on {url}...")

        # Step 1 — Get baseline Content-Length for invalid vhost
        log("  Getting baseline Content-Length for invalid vhost...")
        try:
            baseline_cmd = [
                "curl", "-s", "-I",
                "-H", f"Host: defnotvalid.{domain}",
                "--connect-timeout", "5",
                "-m", "10",
            ]
            if proto == "https":
                baseline_cmd.append("-k")
            baseline_cmd.append(url)

            baseline = sp.run(
                baseline_cmd,
                capture_output=True, text=True, timeout=15
            )

            # Extract Content-Length
            baseline_size = None
            for line in baseline.stdout.split("\n"):
                if "content-length:" in line.lower():
                    baseline_size = line.split(":")[-1].strip()
                    break

            if not baseline_size:
                log(f"  Could not get baseline Content-Length for port {port} — skipping", "warn")
                log(f"  Server may not be running on port {port}", "warn")
                continue

            log(f"  Baseline Content-Length: {baseline_size} (invalid vhost response)")

        except sp.TimeoutExpired:
            log(f"  Baseline check timed out on port {port} — skipping", "warn")
            continue
        except Exception as e:
            log(f"  Baseline check error on port {port}: {e}", "warn")
            continue

        # Step 2 — Run ffuf with baseline filter
        log(f"  Running ffuf against {url} filtering size {baseline_size}...")

        output_file = os.path.join(output_dir, f"06_vhosts_port{port}.txt")

        ffuf_cmd = [
            "ffuf",
            "-w", f"{wordlist}:FUZZ",
            "-u", url,
            "-H", f"Host: FUZZ.{domain}",
            "-fs", baseline_size,
            "-o", output_file,
            "-of", "csv",
            "-t", "50",
            "-timeout", "10",
            "-mc", "all",
            "-ac",
        ]

        if proto == "https":
            ffuf_cmd.extend(["-k"])

        try:
            log(f"  Command: {' '.join(ffuf_cmd)}")
            ffuf_result = sp.run(
                ffuf_cmd,
                capture_output=True, text=True, timeout=300
            )

            # Parse ffuf output for found vhosts
            found_vhosts = []
            for line in ffuf_result.stdout.split("\n"):
                if "[Status:" in line or "200" in line or "301" in line or "302" in line:
                    found_vhosts.append(line.strip())

            # Also check CSV output file
            if os.path.exists(output_file):
                with open(output_file) as f:
                    csv_content = f.read()
                for line in csv_content.split("\n")[1:]:  # Skip header
                    if line.strip() and not line.startswith("url,"):
                        parts = line.split(",")
                        if len(parts) >= 4:
                            vhost    = parts[0].strip()
                            status   = parts[1].strip() if len(parts) > 1 else ""
                            length   = parts[2].strip() if len(parts) > 2 else ""
                            if vhost and vhost != baseline_size:
                                found_vhosts.append(f"{vhost}.{domain} [{status}] size:{length}")

            if found_vhosts:
                log(f"  [!] Found {len(found_vhosts)} vhost(s) on port {port}:", "success")
                for vhost in found_vhosts:
                    log(f"      {vhost}", "success")
                results[port] = found_vhosts

                # Print /etc/hosts tip
                log(f"\n  [TIP] Add discovered vhosts to /etc/hosts:")
                for vhost in found_vhosts:
                    vhost_name = vhost.split()[0] if vhost else ""
                    if vhost_name:
                        log(f"      echo '{target}  {vhost_name}' >> /etc/hosts")
            else:
                log(f"  No vhosts found on port {port} with wordlist {os.path.basename(wordlist)}")
                log(f"  Try a larger wordlist: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")

        except sp.TimeoutExpired:
            log(f"  ffuf timed out on port {port} after 5 minutes", "warn")
        except Exception as e:
            log(f"  ffuf error on port {port}: {e}", "error")

    log("\nVhost discovery complete", "success")
    return results


# ══════════════════════════════════════════════════════════
#  MARKDOWN REPORT (Feature 4 — Obsidian compatible)
# ══════════════════════════════════════════════════════════
def generate_markdown_report(target, open_ports, services, script_results, vuln_results, output_dir):
    """
    Generate an Obsidian-compatible markdown report.
    Follows the machine template format for CPTS.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = []
    md.append(f"# {target}")
    md.append(f"")
    md.append(f"## Host Info")
    md.append(f"| Field | Value |")
    md.append(f"|-------|-------|")
    md.append(f"| IP Address | {target} |")
    md.append(f"| Scan Date | {now} |")
    md.append(f"| Status | 🔴 In Progress |")
    md.append(f"")

    # Open ports table
    md.append(f"## Open Ports")
    md.append(f"| Port | State | Service | Version |")
    md.append(f"|------|-------|---------|---------|")
    for port in open_ports:
        svc  = services.get(port, {})
        name = svc.get('name', 'unknown')
        prod = svc.get('product', '')
        ver  = svc.get('version', '')
        version_str = f"{prod} {ver}".strip()
        md.append(f"| {port}/tcp | open | {name} | {version_str} |")
    md.append(f"")

    # Interesting findings
    all_findings = []
    for port, data in script_results.items():
        output = data.get('output', '')
        for line in output.split('\n'):
            if "@openssh.com" in line:
                continue
            if "NOT VULNERABLE" in line or "not vulnerable" in line:
                continue
            keywords = [
                "VULNERABLE", "vulnerable", "CVE-",
                "Anonymous FTP", "anonymous login", "login allowed",
                "password:", "credential", "root:", "uid=", "id=",
                "No auth", "WRITABLE", "READ/WRITE",
            ]
            if any(kw in line for kw in keywords):
                all_findings.append(f"- `{line.strip()}`")

    if all_findings:
        md.append(f"## Interesting Findings")
        md.extend(all_findings)
        md.append(f"")

    # Vulnerabilities
    if vuln_results:
        md.append(f"## Vulnerabilities")
        for vuln in vuln_results:
            md.append(f"- {vuln}")
        md.append(f"")

    # Enumeration notes
    md.append(f"## Enumeration")
    md.append(f"")
    md.append(f"### Nmap")
    md.append(f"```")
    md.append(f"Output saved to: {output_dir}/02_service_detection.txt")
    md.append(f"```")
    md.append(f"")

    # Exploitation placeholder
    md.append(f"## Exploitation")
    md.append(f"")
    md.append(f"### Vulnerability")
    md.append(f"- Type: ")
    md.append(f"- CVE: ")
    md.append(f"")
    md.append(f"### Steps")
    md.append(f"```bash")
    md.append(f"# paste exploit command here")
    md.append(f"```")
    md.append(f"")

    # Privilege escalation placeholder
    md.append(f"## Privilege Escalation")
    md.append(f"")
    md.append(f"### Method")
    md.append(f"")
    md.append(f"```bash")
    md.append(f"# paste privesc command here")
    md.append(f"```")
    md.append(f"")

    # Flags
    md.append(f"## Flags")
    md.append(f"| Flag | Location | Value |")
    md.append(f"|------|----------|-------|")
    md.append(f"| User | | |")
    md.append(f"| Root | | |")
    md.append(f"")

    # Credentials
    md.append(f"## Credentials Found")
    md.append(f"| Username | Password | Hash | Source |")
    md.append(f"|----------|----------|------|--------|")
    md.append(f"")

    # Rabbit holes
    md.append(f"## Rabbit Holes")
    md.append(f"| Attempt | Why it failed |")
    md.append(f"|---------|--------------|")
    md.append(f"")

    # Notes
    md.append(f"## Notes")
    md.append(f"")

    report = "\n".join(md)
    filepath = save_output(output_dir, f"{target.replace('.', '_')}_notes.md", report)
    log(f"Markdown report saved to: {filepath}", "success")
    return report


def generate_report(target, open_ports, services, script_results, vuln_results, output_dir):
    """Generate a summary report of all findings."""
    log("Generating Summary Report", "section")

    report = []
    report.append(f"ZRecon Summary Report")
    report.append(f"Target: {target}")
    report.append(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"{'='*60}\n")

    # Open ports with script output
    report.append("OPEN PORTS")
    report.append("-"*40)
    report.append(f"  {'PORT':<12} {'STATE':<8} {'SERVICE':<12} VERSION")
    report.append(f"  {'-'*60}")

    for port in open_ports:
        svc_name = services.get(port, {}).get('name', 'unknown')
        product  = services.get(port, {}).get('product', '')
        version  = services.get(port, {}).get('version', '')
        version_str = f"{product} {version}".strip()
        report.append(f"  {str(port)+'/tcp':<12} {'open':<8} {svc_name:<12} {version_str}")

        # Include script output for this port if available
        if port in script_results:
            script_output = script_results[port].get('output', '')
            if script_output:
                # Find the relevant script output section
                in_port_section = False
                for line in script_output.split('\n'):
                    # Start capturing after the port line
                    if f"{port}/tcp" in line:
                        in_port_section = True
                        continue
                    # Stop at next port or end of host section
                    if in_port_section:
                        if line and not line.startswith('|') and not line.startswith('|_') and not line.startswith('SF') and '/tcp' in line and str(port) not in line:
                            break
                        if line.startswith('|') or line.startswith('|_'):
                            # Skip SSH algorithm enumeration lines — noise
                            skip_patterns = [
                                "kex_algorithms",
                                "server_host_key_algorithms",
                                "encryption_algorithms",
                                "mac_algorithms",
                                "compression_algorithms",
                                "curve25519", "ecdh-sha2",
                                "diffie-hellman",
                                "chacha20", "aes128", "aes192", "aes256",
                                "umac-", "hmac-",
                                "zlib@", "none",
                                "rsa-sha2", "ssh-rsa", "ecdsa-sha2",
                                "ssh-ed25519", "ssh2-enum-algos",
                            ]
                            if any(p in line for p in skip_patterns):
                                # Still flag weak algorithms
                                weak = ["arcfour", "3des-cbc", "blowfish-cbc",
                                        "diffie-hellman-group1-sha1",
                                        "diffie-hellman-group14-sha1",
                                        "hmac-md5", "ssh-dss"]
                                if any(w in line for w in weak):
                                    report.append(f"  [WEAK ALGO] {line.strip()}")
                                continue
                            report.append(f"  {line}")

        report.append("")

    report.append("")

    # Script enumeration — clean summary only
    report.append("SCRIPT ENUMERATION")
    report.append("-"*40)

    # All ports share same combined output — parse once, deduplicate
    seen_findings = set()
    interesting_findings = {}

    # Get combined output once (all ports share same file)
    combined_output = ""
    for port, data in script_results.items():
        if data.get("output"):
            combined_output = data["output"]
            break

    # Parse findings once from combined output
    all_found = []
    for line in combined_output.split("\n"):
        if "@openssh.com" in line:
            weak_algos = ["arcfour", "blowfish-cbc", "3des-cbc",
                          "diffie-hellman-group1-sha1",
                          "diffie-hellman-group14-sha1",
                          "hmac-md5", "ssh-dss"]
            if any(w in line for w in weak_algos):
                finding = f"[WEAK ALGO] {line.strip()}"
                if finding not in seen_findings:
                    seen_findings.add(finding)
                    all_found.append((None, "WEAK ALGO", finding))
            continue
        if "NOT VULNERABLE" in line or "not vulnerable" in line:
            continue
        weak_standalone = ["hmac-md5", "ssh-dss", "arcfour", "blowfish-cbc", "3des-cbc"]
        if any(w in line for w in weak_standalone):
            finding = f"[WEAK ALGO] {line.strip()}"
            if finding not in seen_findings:
                seen_findings.add(finding)
                all_found.append((None, "WEAK ALGO", finding))
        keywords = [
            "VULNERABLE", "vulnerable", "CVE-",
            "Anonymous FTP", "anonymous login",
            "login allowed",
            "password:", "credential",
            "root:", "uid=", "id=",
            "No auth", "WRITABLE", "READ/WRITE",
        ]
        if any(kw in line for kw in keywords):
            if line.strip() not in seen_findings:
                seen_findings.add(line.strip())
                # Find which port this finding belongs to by checking port lines above
                all_found.append((None, "FINDING", line.strip()))

    # Associate findings with correct port based on nmap output structure
    current_port = None
    port_findings = {}
    for line in combined_output.split("\n"):
        import re
        port_match = re.match(r'^([0-9]+)/tcp', line.strip())
        if port_match:
            current_port = int(port_match.group(1))
            if current_port not in port_findings:
                port_findings[current_port] = []
        elif current_port and line.strip():
            if "@openssh.com" in line:
                continue
            if "NOT VULNERABLE" in line or "not vulnerable" in line:
                continue
            keywords = [
                "VULNERABLE", "vulnerable", "CVE-",
                "Anonymous FTP", "anonymous login",
                "login allowed", "password:", "credential",
                "root:", "uid=", "id=", "No auth", "WRITABLE", "READ/WRITE",
            ]
            weak_algos = ["arcfour", "blowfish-cbc", "3des-cbc",
                          "diffie-hellman-group1-sha1", "hmac-md5", "ssh-dss"]
            finding = None
            if any(w in line for w in weak_algos):
                finding = f"[WEAK ALGO] {line.strip()}"
            elif any(kw in line for kw in keywords):
                finding = line.strip()
            if finding and finding not in seen_findings:
                seen_findings.add(finding)
                port_findings[current_port].append(finding)

    # Build interesting_findings from port-associated findings
    for port, findings in port_findings.items():
        if findings:
            svc = script_results.get(port, {}).get("service", "unknown")
            interesting_findings[port] = {"service": svc, "findings": findings}

    if interesting_findings:
        for port, data in interesting_findings.items():
            report.append(f"\n  [!] Port {port} — {data['service']}")
            for finding in data["findings"]:
                report.append(f"      {finding}")
    else:
        report.append("  Script enumeration complete — no vulnerabilities found")
        report.append(f"  All output files saved to: {output_dir}")

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
        description="ZRecon — Automated Nmap Enumeration for CPTS/HackTheBox"
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
    parser.add_argument("--vuln",
        action="store_true",
        help="Run vulnerability scan (Phase 5) — disabled by default")
    parser.add_argument("--ports-only",
        action="store_true",
        help="Only perform port discovery — no scripts")
    parser.add_argument("--domain", "-d",
        default=None,
        help="Domain name for DNS enumeration and zone transfer (e.g. inlanefreight.local)")
    parser.add_argument("--vhost",
        action="store_true",
        help="Run vhost discovery using ffuf (requires --domain)")
    parser.add_argument("--vhost-wordlist",
        default=None,
        help="Custom wordlist for vhost discovery (overrides default seclists path)")
    parser.add_argument("--oA",
        action="store_true",
        help="Save nmap output in all formats (.nmap .gnmap .xml) in addition to .txt")

    args = parser.parse_args()

    # Set global oA flag
    global USE_OA
    USE_OA = args.oA

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
    # Use target IP in folder name if user didn't specify custom output dir
    if args.output == OUTPUT_DIR:
        safe_target = args.target.replace('/', '_').replace('\\', '_')
        output_dir = f"zrecon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    else:
        output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    log(f"Output directory: {output_dir}")

    targets = [args.target]

    # Reachability check — skip for subnets (sweep handles that)
    if '/' not in args.target:
        log(f"Checking if target is reachable...")
        reachable, message = check_target_reachable(args.target)
        if reachable:
            log(message, "success")
        else:
            log(f"Target unreachable: {message}", "error")
            log("Aborting scan — fix connectivity and try again", "error")
            sys.exit(1)

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

        # ── Load state for resume support ────────────────
        state        = load_state(target_dir)
        resume_phase = state.get("last_phase", 0)
        if resume_phase > 0:
            log(f"Resuming scan — skipping completed phases up to Phase {resume_phase}", "warn")

        # ── Phase 0 + Phase 1 — DNS + Port Discovery (concurrent) ──
        if resume_phase < 1:
            log("\nRunning Phase 0 (DNS) and Phase 1 (Port Discovery) concurrently...")
            with ThreadPoolExecutor(max_workers=2) as executor:
                dns_future   = None
                ports_future = executor.submit(phase1_port_discovery, target, target_dir)

                if args.domain or (not args.sweep and '/' not in args.target):
                    dns_future = executor.submit(
                        phase0_dns_enumeration,
                        target, target_dir, args.domain
                    )

                open_ports = ports_future.result()

                if dns_future:
                    try:
                        dns_result, discovered_domain = dns_future.result()
                        # Use discovered domain for rest of scan if not already set
                        if discovered_domain and not args.domain:
                            args.domain = discovered_domain
                            log(f"Domain set to: {args.domain} (from DNS enumeration)", "success")
                    except Exception as e:
                        log(f"DNS enumeration error: {e}", "warn")

            save_state(target_dir, 1, {"open_ports": open_ports})
        else:
            open_ports = state.get("open_ports", [])
            log(f"Phase 0/1 already complete — loaded {len(open_ports)} ports from state", "success")

        if not open_ports:
            log(f"No open ports found on {target}", "warn")
            clear_state(target_dir)
            continue

        if args.ports_only:
            log("Ports-only mode — skipping further enumeration")
            clear_state(target_dir)
            continue

        # ── If port 53 found and no domain set yet — retry Phase 0 ──
        if 53 in open_ports and not args.domain:
            log("\nPort 53 open — retrying DNS enumeration against target DNS server...")
            try:
                dns_result, discovered_domain = phase0_dns_enumeration(
                    target=target,
                    output_dir=target_dir,
                    domain=None
                )
                if discovered_domain:
                    args.domain = discovered_domain
                    log(f"Domain discovered: {args.domain}", "success")
            except Exception as e:
                log(f"DNS retry error: {e}", "warn")

        # ── Phase 2 — Service Detection ───────────────────
        if resume_phase < 2:
            services = phase2_service_detection(target, open_ports, target_dir)
            save_state(target_dir, 2, {"services": services})
        else:
            services = state.get("services", {})
            # Convert string keys back to ints (JSON serializes dict keys as strings)
            services = {int(k): v for k, v in services.items()}
            log(f"Phase 2 already complete — loaded from state", "success")

        # ── Phase 3 + 4 — UDP and Scripts (concurrent) ───
        if resume_phase < 3:
            log("\nRunning Phase 3 (UDP) and Phase 4 (Scripts) concurrently...")
            udp_results    = None
            script_results = {}

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {}

                if not args.skip_udp:
                    futures["udp"] = executor.submit(
                        phase3_udp_scan, target, target_dir
                    )

                futures["scripts"] = executor.submit(
                    phase4_script_enumeration, target, open_ports, target_dir, services
                )

                for name, future in futures.items():
                    try:
                        result = future.result()
                        if name == "scripts":
                            script_results = result
                        elif name == "udp":
                            udp_results = result
                    except Exception as e:
                        log(f"Phase {name} error: {e}", "error")

            save_state(target_dir, 3)
        else:
            log(f"Phase 3/4 already complete — loaded from state", "success")
            script_results = {}

        # ── Phase 5 — Vulnerability Scan (opt-in) ─────────
        vuln_results = []
        if args.vuln:
            if resume_phase < 5:
                vuln_results = phase5_vuln_scan(target, open_ports, target_dir)
                save_state(target_dir, 5)
            else:
                log(f"Phase 5 already complete", "success")

        # ── Phase 6 — Vhost Discovery ─────────────────────
        if args.vhost:
            if args.domain:
                http_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
                phase6_vhost_discovery(
                    target=target,
                    output_dir=target_dir,
                    domain=args.domain,
                    ports=http_ports if http_ports else [80],
                    custom_wordlist=args.vhost_wordlist
                )
            else:
                log("--vhost requires --domain to be set e.g. --domain inlanefreight.local", "warn")

        # /etc/hosts already updated by phase0 if domain was discovered
        # If domain was set via --domain flag prompt here
        if args.domain and not args.sweep:
            pass  # Already handled in phase0_dns_enumeration

        # ── Generate Reports ──────────────────────────────
        generate_report(
            target=target,
            open_ports=open_ports,
            services=services,
            script_results=script_results,
            vuln_results=vuln_results,
            output_dir=target_dir
        )

        generate_markdown_report(
            target=target,
            open_ports=open_ports,
            services=services,
            script_results=script_results,
            vuln_results=vuln_results,
            output_dir=target_dir
        )

        # ── Clear state on successful completion ──────────
        clear_state(target_dir)

    log("\nAutorecon complete!", "success")
    log(f"All output saved to: {output_dir}", "success")


if __name__ == "__main__":
    main()
