import argparse
import csv
import json
import os
import socket
import sys
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from enrichment import detect_firewall, detect_os, discover_hosts, get_geolocation, get_route_table, reverse_dns
from scanner_core import scan_port
from validators import extract_domain, parse_port_targets


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"


STYLE_ENABLED = True
QUIET = False
TOOL_NAME = "PortSpectre CLI"


def paint(text, color):
    if not STYLE_ENABLED:
        return text
    return f"{color}{text}{C.RESET}"


def banner():
    print(paint("  ____            _     ____                                  ", C.GREEN + C.BOLD))
    print(paint(" |  _ \\ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __", C.GREEN + C.BOLD))
    print(paint(" | |_) / _ \\| '__| __| \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|", C.GREEN + C.BOLD))
    print(paint(" |  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   ", C.GREEN + C.BOLD))
    print(paint(" |_|   \\___/|_|   \\__| |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   ", C.GREEN + C.BOLD))
    print(paint(f"                [ {TOOL_NAME} ]", C.CYAN))


def progress_bar(done, total, width=36):
    if total <= 0:
        return "[------------------------------------] 0.0%"
    ratio = min(max(done / total, 0.0), 1.0)
    fill = int(width * ratio)
    bar = "#" * fill + "-" * (width - fill)
    return f"[{bar}] {ratio * 100:5.1f}% ({done}/{total})"


def log_line(level, message):
    if QUIET and level == "INFO":
        return
    color = C.GREEN
    if level == "WARN":
        color = C.YELLOW
    elif level == "ERR":
        color = C.RED
    print(paint(f"[{level}] {message}", color))


def normalize_args(args):
    if args.workers < 1:
        raise ValueError("--workers must be >= 1")
    if args.timeout <= 0:
        raise ValueError("--timeout must be > 0")
    if args.retries < 0:
        raise ValueError("--retries must be >= 0")
    if args.delay < 0:
        raise ValueError("--delay must be >= 0")
    if args.timing < 0 or args.timing > 5:
        raise ValueError("-T must be between 0 and 5")


def ensure_parent_dir(path):
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def classify_status(status):
    s = str(status or "").lower()
    if "open" in s:
        return "open"
    if "closed" in s:
        return "closed"
    if "filter" in s:
        return "filtered"
    if "error" in s or "unsupported" in s or "exception" in s:
        return "error"
    return "other"


def port_sort_value(value):
    try:
        return int(value)
    except Exception:
        return 999999


def protocol_for_scan(scan_type):
    return "tcp" if scan_type in ("SYN", "STEALTH", "CONNECT") else "udp"


def port_state(status):
    s = str(status or "").lower()
    if "open" in s:
        return "open"
    if "closed" in s:
        return "closed"
    if "filter" in s:
        return "filtered"
    return "unknown"


def apply_timing_profile(args):
    profiles = {
        0: {"workers": 25, "timeout": 3.0, "retries": 2, "delay": 0.05},
        1: {"workers": 60, "timeout": 2.0, "retries": 1, "delay": 0.02},
        2: {"workers": 120, "timeout": 1.2, "retries": 1, "delay": 0.005},
        3: {"workers": 250, "timeout": 0.8, "retries": 0, "delay": 0.0},
        4: {"workers": 450, "timeout": 0.45, "retries": 0, "delay": 0.0},
        5: {"workers": 700, "timeout": 0.25, "retries": 0, "delay": 0.0},
    }
    selected = profiles[args.timing]
    args.workers = selected["workers"] if args.workers is None else args.workers
    args.timeout = selected["timeout"] if args.timeout is None else args.timeout
    args.retries = selected["retries"] if args.retries is None else args.retries
    args.delay = selected["delay"] if args.delay is None else args.delay


def print_scan_report(target, metadata, visible_rows, all_rows, scan_type):
    proto = protocol_for_scan(scan_type)
    print(f"{TOOL_NAME} report for {target}")
    print()
    all_by_host = {}
    for r in all_rows:
        all_by_host.setdefault(r.get("host", "unknown"), []).append(r)
    visible_by_host = {}
    for r in visible_rows:
        visible_by_host.setdefault(r.get("host", "unknown"), []).append(r)

    for host in sorted(all_by_host.keys()):
        host_all_rows = all_by_host[host]
        host_rows = sorted(visible_by_host.get(host, []), key=lambda r: port_sort_value(r.get("port")))
        closed_count = sum(1 for r in host_all_rows if port_state(r.get("status")) == "closed")
        filtered_count = sum(1 for r in host_all_rows if port_state(r.get("status")) == "filtered")
        print(f"Scan report for {host}")
        print("Host is up.")
        if closed_count > 0:
            print(f"Not shown: {closed_count} closed {proto} ports")
        if filtered_count > 0:
            print(f"Filtered: {filtered_count} {proto} ports")
        print("PORT      STATE     SERVICE          VERSION")
        for r in host_rows:
            port_text = f"{r.get('port')}/{proto}"
            state = port_state(r.get("status"))
            service = str(r.get("service", "unknown"))[:16]
            version = str(r.get("version", "")).strip() or "-"
            print(f"{port_text:<9} {state:<9} {service:<16} {version}")
        print()

    summary = metadata.get("summary", {})
    print(
        "Scan complete: "
        f"{summary.get('total_scanned', 0)} ports scanned in "
        f"{summary.get('elapsed_seconds', 0)} seconds"
    )


def install_scapy_thread_exception_filter():
    original = threading.excepthook

    def filtered_excepthook(args):
        exc = args.exc_value
        tb_text = ""
        if args.exc_traceback is not None:
            tb_text = " ".join(frame.filename.lower() for frame in traceback.extract_tb(args.exc_traceback))
        if (
            isinstance(exc, OSError)
            and getattr(exc, "errno", None) == 9
            and "scapy" in tb_text
        ):
            return
        original(args)

    threading.excepthook = filtered_excepthook
    return original


def resolve_targets(target_raw, scan_all_hosts=False):
    target = extract_domain(target_raw)
    if not target:
        raise ValueError("No target specified.")
    if "/" in target:
        alive = discover_hosts(target)
        if not alive:
            raise ValueError("No alive hosts discovered for CIDR target.")
        return target, "cidr", alive if scan_all_hosts else [alive[0]], alive
    try:
        infos = socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos if info and info[4]})
        if not ips:
            raise ValueError("No IPv4 address resolved for target.")
    except Exception as exc:
        raise ValueError("Invalid domain or IP.") from exc
    return target, "single", ips if scan_all_hosts else [ips[0]], ips


def export_csv(path, result_rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Host", "Port", "Service", "Status", "Version"])
        for r in result_rows:
            w.writerow([r.get("host", ""), r.get("port", ""), r.get("service", ""), r.get("status", ""), r.get("version", "")])


def export_md(path, metadata, result_rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# PortSpectre CLI Report\n\n")
        for k, v in metadata.items():
            f.write(f"- **{k}**: {v}\n")
        f.write("\n## Results\n\n")
        f.write("| Host | Port | Service | Status | Version |\n")
        f.write("|---|---:|---|---|---|\n")
        for r in result_rows:
            version = str(r.get("version", "")).replace("|", "\\|")
            f.write(f"| {r.get('host','')} | {r.get('port','')} | {r.get('service','')} | {r.get('status','')} | {version} |\n")


def run(args):
    global STYLE_ENABLED, QUIET
    STYLE_ENABLED = (not args.no_color) and ("NO_COLOR" not in os.environ)
    QUIET = args.quiet

    apply_timing_profile(args)
    normalize_args(args)
    if not args.no_banner:
        banner()
    ports, port_query = parse_port_targets(args.port_range, args.ports)
    target, mode, scan_hosts, alive_hosts = resolve_targets(args.target, args.scan_all_hosts)
    scan_type = args.scan_type.upper()
    effective_workers = args.workers
    if scan_type in ("SYN", "UDP", "STEALTH") and args.workers > 1:
        effective_workers = 1
        log_line("WARN", f"{scan_type} uses serialized raw packets here; forcing workers=1 for stability.")

    log_line("INFO", f"Target: {target} | Mode: {mode}")
    log_line("INFO", f"Alive hosts: {', '.join(alive_hosts)}")
    log_line("INFO", f"Scan type: {scan_type} | Ports: {port_query}")

    primary_ip = scan_hosts[0]
    metadata = {
        "target": target,
        "mode": mode,
        "primary_ip": primary_ip,
        "resolved_ips": alive_hosts,
        "port_query": port_query,
        "scan_type": scan_type,
        "timing_template": args.timing,
        "workers": effective_workers,
        "timeout": args.timeout,
        "retries": args.retries,
        "delay": args.delay,
        "service_version": args.service_version,
    }
    metadata["hostname"] = reverse_dns(primary_ip) or "N/A"
    if args.aggressive:
        metadata["os_guess"] = detect_os(primary_ip)
        metadata["firewall"] = detect_firewall(primary_ip, host_header=target)
        geo = get_geolocation(primary_ip)
        metadata["geo"] = f"{geo.get('city','Unknown')}, {geo.get('region','Unknown')}, {geo.get('country','Unknown')}"

    if args.include_route:
        route = get_route_table(primary_ip)
        if route:
            log_line("INFO", "Route table:")
            for hop in route:
                print(f"  hop {hop.get('hop')}: {hop.get('ip')} rtt={hop.get('rtt_ms')}ms [{hop.get('status')}]")
        else:
            log_line("WARN", "No route table data.")

    total = len(scan_hosts) * len(ports)
    done = 0
    started = time.time()
    rows = []

    print()
    if not args.quiet:
        log_line("INFO", f"Initializing {scan_type} scan engine...")
    status_counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0, "other": 0}
    show_progress = sys.stdout.isatty() and not args.quiet
    spinner_frames = [
        "[>      ]",
        "[>>     ]",
        "[>>>    ]",
        "[ >>>   ]",
        "[  >>>  ]",
        "[   >>> ]",
        "[    >>>]",
        "[     >>]",
        "[      >]",
        "[     < ]",
        "[    <<<]",
        "[   <<< ]",
        "[  <<<  ]",
        "[ <<<   ]",
        "[<<<    ]",
        "[<<     ]",
    ]
    spin_idx = 0
    last_draw = 0.0
    with ThreadPoolExecutor(max_workers=effective_workers) as ex:
        previous_hook = install_scapy_thread_exception_filter()
        try:
            fmap = {}
            for host in scan_hosts:
                for p in ports:
                    f = ex.submit(
                        scan_port,
                        host,
                        p,
                        scan_type,
                        args.timeout,
                        args.retries,
                        args.delay,
                        target,
                        args.service_version,
                    )
                    fmap[f] = host

            for future in as_completed(fmap):
                host = fmap[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {"port": "?", "service": "Error", "status": f"Exception: {exc}", "version": "", "details": {}}
                row["host"] = host
                rows.append(row)
                done += 1
                state = row.get("status", "Unknown")
                status_counts[classify_status(state)] += 1
                if show_progress:
                    now = time.time()
                    if now - last_draw >= 0.06 or done == total:
                        frame = spinner_frames[spin_idx % len(spinner_frames)]
                        spin_idx += 1
                        pct = (done / total * 100.0) if total else 0.0
                        line = (
                            f"{frame} {scan_type} SCAN "
                            f"{done}/{total} ({pct:5.1f}%) "
                            f"open:{status_counts['open']} filtered:{status_counts['filtered']} "
                            f"closed:{status_counts['closed']} err:{status_counts['error']}"
                        )
                        print(paint(line, C.CYAN), end="\r")
                        last_draw = now
        finally:
            threading.excepthook = previous_hook

    elapsed = time.time() - started
    if show_progress:
        print(" " * 120, end="\r")
    print()
    log_line("INFO", f"Scan completed in {elapsed:.2f}s")
    log_line(
        "INFO",
        (
            f"Summary: open={status_counts['open']} closed={status_counts['closed']} "
            f"filtered={status_counts['filtered']} error={status_counts['error']} other={status_counts['other']}"
        ),
    )

    all_rows = list(rows)
    if not args.show_all:
        rows = [r for r in rows if "open" in str(r.get("status", "")).lower()]

    rows = sorted(rows, key=lambda x: (x.get("host", ""), port_sort_value(x.get("port", 0))))

    metadata["summary"] = {
        "total_scanned": total,
        "elapsed_seconds": round(elapsed, 3),
        **status_counts,
        "visible_results": len(rows),
    }
    print_scan_report(target, metadata, rows, all_rows, scan_type)
    if not rows:
        log_line("WARN", "No visible results for current filters.")

    if args.json_out:
        ensure_parent_dir(args.json_out)
        payload = {"metadata": metadata, "results": rows}
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        log_line("INFO", f"JSON saved -> {args.json_out}")
    if args.csv_out:
        ensure_parent_dir(args.csv_out)
        export_csv(args.csv_out, rows)
        log_line("INFO", f"CSV saved -> {args.csv_out}")
    if args.md_out:
        ensure_parent_dir(args.md_out)
        export_md(args.md_out, metadata, rows)
        log_line("INFO", f"Markdown saved -> {args.md_out}")


def build_parser():
    p = argparse.ArgumentParser(description="PortSpectre CLI")
    p.add_argument("target", help="Domain, IP, or CIDR target")
    p.add_argument("--ports", type=int, default=1000, help="Count mode: scan first N ports (default: 1000)")
    p.add_argument("--port-range", default="", help="Range/list mode: e.g. 1-1024,3306,8080")
    p.add_argument("--scan-type", choices=["SYN", "UDP", "STEALTH", "CONNECT"], default="CONNECT")
    p.add_argument("-T", "--timing", type=int, default=4, help="Timing template 0(slowest)-5(fastest), default: 4")
    p.add_argument("--workers", type=int, default=None, help="Override worker count (default from -T profile)")
    p.add_argument("--timeout", type=float, default=None, help="Override timeout in seconds (default from -T profile)")
    p.add_argument("--retries", type=int, default=None, help="Override retries (default from -T profile)")
    p.add_argument("--delay", type=float, default=None, help="Override per-request delay seconds (default from -T profile)")
    p.add_argument("-sV", "--service-version", action="store_true", help="Enable service/version detection on open TCP ports")
    p.add_argument("-A", "--aggressive", action="store_true", help="Enable aggressive host enrichment (OS/firewall/geo)")
    p.add_argument("--show-all", action="store_true", help="Show non-open results too")
    p.add_argument("--include-route", action="store_true", help="Show route table")
    p.add_argument("--scan-all-hosts", action="store_true", help="For CIDR: scan all alive hosts. For domain: scan all resolved IPv4 IPs.")
    p.add_argument("--quiet", action="store_true", help="Reduce console output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="Disable banner output")
    p.add_argument("--json-out", default="", help="Write JSON report")
    p.add_argument("--csv-out", default="", help="Write CSV report")
    p.add_argument("--md-out", default="", help="Write Markdown report")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        log_line("WARN", "Interrupted by user.")
        raise SystemExit(130)
    except Exception as exc:
        log_line("ERR", str(exc))
        raise SystemExit(1)
