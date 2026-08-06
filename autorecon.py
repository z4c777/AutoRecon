#!/usr/bin/env python3
"""
AutoRecon — Automated Nmap Enumeration Script
For authorized penetration testing only (HackTheBox, CPTS, etc.)

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
            log("If the host is up but blocking ping try: python3 autorecon.py -t TARGET (nmap uses -Pn by default)", "warn")
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

        # Store output for each port and highlight findings
        for port in tcp_ports:
            svc_config = port_svc_map.get(port, {})
            svc_name   = svc_config.get("name", "unknown")

            results[port] = {
                "service": svc_name,
                "scripts": svc_config.get("scripts", ""),
                "output":  output
            }

            # Highlight interesting findings
            for line in output.split('\n'):
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
                keywords = ["VULNERABLE", "vulnerable", "CVE-",
                            "Anonymous", "anonymous", "password:",
                            "credential", "admin", "root",
                            "ERROR", "open", "uid=", "id="]
                if any(kw in line for kw in keywords):
                    log(f"  [INTERESTING] {line.strip()}", "warn")

        # Post-scan tips for all TCP services
        for port in tcp_ports:
            svc_name = port_svc_map.get(port, {}).get("name", "")
            post_scan_tips(port, svc_name, target)

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
def generate_report(target, open_ports, services, script_results, vuln_results, output_dir):
    """Generate a summary report of all findings."""
    log("Generating Summary Report", "section")

    report = []
    report.append(f"AutoRecon Summary Report")
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

    interesting_findings = {}
    for port, data in script_results.items():
        svc    = data["service"]
        output = data.get("output", "")
        found  = []
        for line in output.split("\n"):
            if "@openssh.com" in line:
                # Flag weak algorithms even in openssh.com lines
                weak_algos = [
                    "arcfour", "blowfish-cbc", "3des-cbc",
                    "diffie-hellman-group1-sha1",
                    "diffie-hellman-group14-sha1",
                    "hmac-md5", "ssh-dss",
                ]
                if any(w in line for w in weak_algos):
                    found.append(f"[WEAK ALGO] {line.strip()}")
                continue
            if "NOT VULNERABLE" in line or "not vulnerable" in line:
                continue
            weak_standalone = ["hmac-md5", "ssh-dss", "arcfour", "blowfish-cbc", "3des-cbc"]
            if any(w in line for w in weak_standalone):
                found.append(f"[WEAK ALGO] {line.strip()}")
            keywords = [
                "VULNERABLE", "vulnerable", "CVE-",
                "Anonymous login", "anonymous login",
                "password:", "credential",
                "root:", "uid=", "id=",
                "WRITABLE", "No authentication",
                "READ/WRITE",
            ]
            if any(kw in line for kw in keywords):
                found.append(line.strip())
        if found:
            interesting_findings[port] = {"service": svc, "findings": found}

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
    parser.add_argument("--vuln",
        action="store_true",
        help="Run vulnerability scan (Phase 5) — disabled by default")
    parser.add_argument("--ports-only",
        action="store_true",
        help="Only perform port discovery — no scripts")
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
        output_dir = f"autorecon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
        script_results = phase4_script_enumeration(target, open_ports, target_dir, services)

        # Phase 5 — Vulnerability Scan (opt-in only)
        vuln_results = []
        if args.vuln:
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
