# AutoRecon 🔍

A Python reconnaissance framework that wraps Nmap with automatic service detection, targeted NSE script selection, concurrent scanning, DNS enumeration, vhost discovery, and structured output for penetration testing.

Built for HackTheBox CPTS.

---

## Install

```bash
git clone https://github.com/z4c777/AutoRecon && \
pip install python-nmap paramiko && \
sudo apt install -y nmap seclists ffuf rpcbind
```

## Run

```bash
cd AutoRecon
python3 autorecon.py -t TARGET
```

---

## Usage

```bash
python3 autorecon.py -t TARGET [options]
```

| Flag | Description |
|------|-------------|
| `-t` | Target IP, hostname, or CIDR (required) |
| `-d`, `--domain` | Domain for DNS enumeration e.g. `inlanefreight.local` |
| `-o` | Custom output directory |
| `--sweep` | Ping sweep subnet, scan each live host |
| `--skip-udp` | Skip UDP scan |
| `--vuln` | Run vulnerability scan |
| `--vhost` | Run vhost discovery (requires `--domain`) |
| `--vhost-wordlist` | Custom wordlist for vhost discovery |
| `--ports-only` | Port discovery only |
| `--oA` | Save nmap output in all formats |

### Examples

```bash
# Basic scan
python3 autorecon.py -t 10.129.98.84

# With DNS enumeration and vhost discovery
python3 autorecon.py -t 10.129.98.84 --domain inlanefreight.local --vhost

# Subnet sweep
python3 autorecon.py -t 10.129.1.0/24 --sweep

# Full scan with vuln check
python3 autorecon.py -t 10.129.98.84 --domain inlanefreight.local --vhost --vuln
```

---

## How It Works

```
Phase 0  DNS enumeration       Record lookup + zone transfer  (--domain)
Phase 1  TCP port discovery    nmap -p- --min-rate 5000
Phase 2  Service detection     nmap -sCV on open ports only
Phase 3  UDP scan       ┐ concurrent
Phase 4  NSE scripts    ┘      All scripts in one nmap call
Phase 5  Vuln scan             nmap --script 'vuln and safe'  (--vuln)
Phase 6  Vhost discovery       ffuf baseline method           (--vhost)
```

Beyond NSE scripts the tool runs active checks automatically:
- **SSH** — tests common default credentials via paramiko
- **SMTP** — enumerates users via VRFY command
- **RPC** — runs `rpcinfo` binary when port 111 is found

---

## Output

```
autorecon_10.129.98.84_20260805_224943/
├── 00_summary_report.txt     All findings
├── 10_129_98_84_notes.md     Obsidian-ready notes
├── 00_dns_enum.txt           DNS records
├── 01_open_ports.txt         Open TCP ports
├── 02_service_detection.txt  Service versions
├── 03_udp_scan.txt           UDP results
├── 04_tcp_scripts.txt        NSE script output
└── 05_vuln_scan.txt          Vuln findings
```

If interrupted — re-run the same command to resume from where it left off.

---

## Disclaimer

For authorized penetration testing and CTF environments only.
