# PortSpectre CLI

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/VeerDev-hub/Port-Scanner)
[![Repo](https://img.shields.io/badge/repo-Port--Scanner-black)](https://github.com/VeerDev-hub/Port-Scanner)
[![Stars](https://img.shields.io/github/stars/VeerDev-hub/Port-Scanner?style=social)](https://github.com/VeerDev-hub/Port-Scanner/stargazers)

Fast hacker-style port scanner CLI with clean terminal output, progress animation, JSON/CSV/Markdown exports, and one-command build scripts.

## Features

- Multi-mode scanning: `CONNECT`, `SYN`, `UDP`, `STEALTH`
- Timing profiles: `-T0` to `-T5`
- Optional service/version detection: `-sV`
- Optional aggressive enrichment: `-A`
- CIDR scan support with `--scan-all-hosts`
- Export reports to `json`, `csv`, and `md`
- Minimal output mode: `--quiet`

## Quick Start

```powershell
python portscanner_cli.py scanme.nmap.org --scan-type CONNECT -T 4 --ports 300
```

### Useful Commands

```powershell
# Fast connect scan
python portscanner_cli.py scanme.nmap.org --scan-type CONNECT -T 4 --ports 1000 --no-banner

# Service/version detection
python portscanner_cli.py scanme.nmap.org --scan-type CONNECT -T 4 --port-range 22,80,443 -sV --no-banner

# CIDR scan (all alive hosts)
python portscanner_cli.py 192.168.1.0/24 --scan-all-hosts --port-range 22,80,443 --scan-type CONNECT -T 4 --no-banner

# Export reports
python portscanner_cli.py scanme.nmap.org --scan-type CONNECT -T 4 --ports 300 --json-out reports/scan.json --csv-out reports/scan.csv --md-out reports/scan.md --no-banner
```

## One-Command Builds

### Windows

```powershell
.\build.ps1
```

Clean rebuild:

```powershell
.\build.ps1 -Clean
```

Output artifact:

- `dist/portspectre.exe`

### Linux/macOS

```bash
chmod +x build.sh
./build.sh
```

Clean rebuild:

```bash
./build.sh --clean
```

Output artifact:

- `dist/portspectre`

## Linux Packaging Notes

- `CONNECT` mode runs as normal user.
- `SYN/UDP/STEALTH` need elevated privileges or capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./dist/portspectre
```

## CLI Options (high value)

- `--ports N`: scan first `N` ports
- `--port-range`: custom ranges/lists (example `1-1024,3306,8080`)
- `--scan-type`: `SYN|UDP|STEALTH|CONNECT`
- `-T`: timing profile `0..5`
- `-sV`: enable service/version detection
- `-A`: enable aggressive enrichment
- `--show-all`: include non-open results
- `--scan-all-hosts`: scan all alive hosts for CIDR (and all resolved IPv4s for domain)
- `--quiet`: hide informational logs
- `--json-out`, `--csv-out`, `--md-out`: export reports

## Disclaimer

Use this tool only on systems/networks you own or have explicit permission to test.
