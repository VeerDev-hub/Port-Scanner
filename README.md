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
- Top-ports profiles: `--top-ports 100|1000|5000`
- State filtering: `--only-state open|closed|filtered|unknown`
- Exclusion support: `--exclude-ports`
- Scan diff mode: `--compare old.json new.json`
- Inventory summary mode: `--inventory`
- Plugin enrichment system: `--plugin-dir plugins`
- Basic TUI-style dashboard: `--tui`
- Rate limiting and adaptive timeout: `--rate`, `--adaptive-timeout`
- Public-target legal acknowledgment: `--i-understand`
- CIDR scan support with `--scan-all-hosts`
- Export reports to `json`, `csv`, and `md`
- Minimal output mode: `--quiet`

## PortSpectre vs Nmap (Quick View)

- PortSpectre: lightweight CLI focused on fast scans, clean output, and exportable reports.
- Nmap: full recon suite with advanced fingerprinting, NSE scripts, and deep scan techniques.
- Use PortSpectre for quick assessments and reporting; use Nmap for exhaustive recon.

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

# Top ports with exclusions and state filter
python portscanner_cli.py scanme.nmap.org --top-ports 1000 --exclude-ports 445,3389 --only-state open --i-understand

# Compare two JSON reports
python portscanner_cli.py --compare reports/old.json reports/new.json

# Inventory + dashboard
python portscanner_cli.py 192.168.1.0/24 --scan-all-hosts --port-range 22,80,443 --inventory --tui
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

## Debian Package Build

```bash
chmod +x build.sh package_deb.sh
./build.sh --clean
./package_deb.sh
```

Output artifact:

- `dist/portspectre_<version>_amd64.deb`

## Linux Packaging Notes

- `CONNECT` mode runs as normal user.
- `SYN/UDP/STEALTH` need elevated privileges or capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./dist/portspectre
```

## CLI Options (high value)

- `--ports N`: scan first `N` ports
- `--port-range`: custom ranges/lists (example `1-1024,3306,8080`)
- `--top-ports`: common-port profile count
- `--exclude-ports`: remove ports from active target set
- `--scan-type`: `SYN|UDP|STEALTH|CONNECT`
- `-T`: timing profile `0..5`
- `-sV`: enable service/version detection
- `--adaptive-timeout`: increase timeout per retry
- `--rate`: max probe submissions per second
- `-A`: enable aggressive enrichment
- `--show-all`: include non-open results
- `--only-state`: show a single state category
- `--scan-all-hosts`: scan all alive hosts for CIDR (and all resolved IPv4s for domain)
- `--compare old.json new.json`: report opened/closed deltas
- `--inventory`: host summary table
- `--plugin-dir`: load custom enrichment plugins
- `--tui`: print compact dashboard
- `--i-understand`: required for public target scans
- `--quiet`: hide informational logs
- `--json-out`, `--csv-out`, `--md-out`: export reports

## Integration Testing

```bash
chmod +x integration/test_integration.sh
./integration/test_integration.sh
```

## Disclaimer

Use this tool only on systems/networks you own or have explicit permission to test.
