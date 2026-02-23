import platform
import re
import socket
import ssl
import subprocess
import time
import ipaddress

import requests
from scapy.all import IP, TCP, sr1
import socket as pysock


def get_geolocation(ip):
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": data.get("ip", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "loc": data.get("loc", "Unknown"),
                "org": data.get("org", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
            }
    except Exception:
        pass
    return {"error": "Geolocation lookup failed"}


def reverse_dns(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def get_route_table(ip, max_hops=20, timeout_seconds=1.0):
    hops = []
    try:
        if platform.system().lower() == "windows":
            wait_ms = int(max(100, timeout_seconds * 1000))
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(wait_ms), ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_seconds), ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        output = (result.stdout or "") + "\n" + (result.stderr or "")

        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not match:
                continue
            hop_number = int(match.group(1))
            payload = match.group(2).strip()
            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", payload)
            rtts = re.findall(r"(\d+(?:\.\d+)?)\s*ms", payload, re.IGNORECASE)

            if ip_match:
                hop_ip = ip_match.group(1)
                avg_rtt = round(sum(float(v) for v in rtts) / len(rtts), 2) if rtts else None
                hops.append({"hop": hop_number, "ip": hop_ip, "rtt_ms": avg_rtt, "status": "Reached"})
            elif "*" in payload:
                hops.append({"hop": hop_number, "ip": "*", "rtt_ms": None, "status": "Timed Out"})
    except Exception:
        pass
    return hops


def detect_firewall(ip, host_header=None):
    hints = []
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        if host_header:
            headers["Host"] = host_header
        r = requests.get(f"http://{ip}", headers=headers, timeout=1.5)
        server = r.headers.get("Server", "")
        via = r.headers.get("Via", "")
        cf_ray = r.headers.get("CF-RAY", "")
        akamai = r.headers.get("X-Akamai-Transformed", "") or r.headers.get("Akamai-Origin-Hop", "")
        powered = r.headers.get("X-Powered-By", "")
        merged = (server + via + cf_ray + str(akamai) + powered).lower()
        if "cloudflare" in merged:
            hints.append("Cloudflare")
        if "akamai" in merged:
            hints.append("Akamai")
        if "sucuri" in merged:
            hints.append("Sucuri")
        if "imperva" in merged or "incapsula" in merged:
            hints.append("Imperva/Incapsula")
        if "aws" in merged or ".amazonaws." in (r.text or "").lower():
            hints.append("AWS Layer/ALB")
        if not hints and (server or via or powered):
            hints.append(server or via or powered)
    except Exception:
        pass

    try:
        info = requests.get(f"https://ipinfo.io/{ip}/json", headers={"User-Agent": "Mozilla/5.0"}, timeout=2)
        if info.status_code == 200:
            org = (info.json().get("org") or "").lower()
            if "cloudflare" in org:
                hints.append("Cloudflare (ASN)")
            if "akamai" in org:
                hints.append("Akamai (ASN)")
            if "fastly" in org:
                hints.append("Fastly (ASN)")
            if "incapsula" in org or "imperva" in org:
                hints.append("Imperva (ASN)")
    except Exception:
        pass

    if not hints:
        return "Unknown/No obvious WAF"
    seen = set()
    ordered = []
    for item in hints:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ", ".join(ordered)


def detect_os(ip):
    try:
        ping_cmd = ["ping", "-n", "1", ip] if platform.system().lower() == "windows" else ["ping", "-c", "1", ip]
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(r"ttl\s*[=:\s]\s*(\d+)", output, re.IGNORECASE)
        if match:
            ttl_value = int(match.group(1))
            if ttl_value <= 64:
                return "Linux/Unix-based OS"
            if ttl_value <= 128:
                return "Windows OS"
            return "Network Device (Router/Switch)"
    except Exception:
        pass

    try:
        for test_port in (443, 80):
            pkt = IP(dst=ip) / TCP(dport=test_port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                continue
            ttl_val = int(resp[IP].ttl)
            if ttl_val <= 64:
                return "Linux/Unix-based OS"
            if ttl_val <= 128:
                return "Windows OS"
            return "Network Device (Router/Switch)"
    except Exception:
        pass
    return "Unknown (TTL not observed)"


def get_tls_info(ip, port=443, server_name=None, timeout_seconds=1.5):
    try:
        context = ssl.create_default_context()
        with pysock.create_connection((ip, port), timeout=timeout_seconds) as raw:
            with context.wrap_socket(raw, server_hostname=(server_name or ip)) as tls:
                cert = tls.getpeercert()
                subject = ", ".join(["=".join(x) for r in cert.get("subject", []) for x in r])
                issuer = ", ".join(["=".join(x) for r in cert.get("issuer", []) for x in r])
                san = ", ".join([v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]) or None
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": san,
                }
    except Exception as exc:
        return {"error": str(exc)}


def http_enrich(ip, port, use_https=False, host_header=None, timeout_seconds=1.5):
    try:
        scheme = "https" if use_https else "http"
        host = host_header or ip
        url = f"{scheme}://{host}:{port}/"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout_seconds, allow_redirects=True)
        title_match = re.search(r"<title>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else None
        headers_interest = {
            k: r.headers.get(k)
            for k in ["Server", "X-Powered-By", "Via", "Location"]
            if r.headers.get(k)
        }
        return {"status": r.status_code, "title": title, "headers": headers_interest}
    except Exception as exc:
        return {"error": str(exc)}


def _host_alive(ip, timeout_seconds=0.6):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    return False


def discover_hosts(cidr_target, max_hosts=256):
    try:
        network = ipaddress.ip_network(cidr_target, strict=False)
    except Exception:
        return []

    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]

    alive = []
    for ip in hosts:
        if _host_alive(ip):
            alive.append(ip)
    return alive
