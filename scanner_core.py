import socket
import ssl
import socket as pysock
import time
import threading

from scapy.all import IP, TCP, UDP, ICMP, sr1, RandShort

from enrichment import http_enrich, get_tls_info


SCAPY_LOCK = threading.Lock()


COMMON_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy",
    5000: "UPnP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    65535: "Dynamic End",
}


def get_port_service(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return COMMON_PORTS.get(port, "Unknown Service")


def banner_grab(ip, port, timeout_seconds=0.8, host_header=None):
    def single_line(text):
        if not text:
            return ""
        first = text.splitlines()[0].strip()
        return " ".join(first.split())

    try:
        with pysock.create_connection((ip, port), timeout=timeout_seconds) as s:
            s.settimeout(timeout_seconds)
            try:
                if port in (80, 8080, 8000, 8888):
                    host_val = (host_header or ip).encode()
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host_val + b"\r\nConnection: close\r\n\r\n")
                elif port == 443:
                    context = ssl.create_default_context()
                    with context.wrap_socket(s, server_hostname=(host_header or ip)) as tls:
                        req = f"HEAD / HTTP/1.1\r\nHost: {host_header or ip}\r\nConnection: close\r\n\r\n".encode()
                        tls.sendall(req)
                        return single_line(tls.recv(512).decode(errors="ignore"))
                data = s.recv(256)
                return single_line(data.decode(errors="ignore"))
            except Exception:
                return ""
    except Exception:
        return ""


def enrich_open_port(ip, port, host_header, timeout_seconds):
    details = {}
    if port in (80, 8080, 8000, 8888):
        details["http"] = http_enrich(ip, port, use_https=False, host_header=host_header, timeout_seconds=timeout_seconds)
    if port == 443:
        details["http"] = http_enrich(ip, port, use_https=True, host_header=host_header, timeout_seconds=timeout_seconds)
        details["tls"] = get_tls_info(ip, port=443, server_name=host_header, timeout_seconds=timeout_seconds)
    return details


def scan_port(
    ip,
    port,
    scan_type="SYN",
    timeout_seconds=1.0,
    retries=0,
    delay_seconds=0.0,
    host_header=None,
    service_version=False,
):
    try:
        if delay_seconds > 0:
            time.sleep(delay_seconds)

        if scan_type == "SYN":
            pkt = IP(dst=ip, ttl=64) / TCP(sport=RandShort(), dport=port, flags="S")
            response = None
            attempts = 0
            while attempts <= retries:
                with SCAPY_LOCK:
                    response = sr1(pkt, timeout=timeout_seconds, verbose=0)
                if response is not None:
                    break
                attempts += 1
            if response is None:
                status = "Filtered or No Response"
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    with SCAPY_LOCK:
                        sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
                    status = "Open"
                elif response[TCP].flags == 0x14:
                    status = "Closed"
                else:
                    status = "Unknown TCP Response"
            else:
                status = "Unknown Response"

        elif scan_type == "UDP":
            pkt = IP(dst=ip, ttl=64) / UDP(sport=RandShort(), dport=port)
            response = None
            attempts = 0
            while attempts <= retries:
                with SCAPY_LOCK:
                    response = sr1(pkt, timeout=max(timeout_seconds, 2.0), verbose=0)
                if response is not None:
                    break
                attempts += 1
            if response is None:
                status = "Open|Filtered"
            elif response.haslayer(UDP):
                status = "Open"
            elif response.haslayer(ICMP):
                status = "Closed"
            else:
                status = "Unknown Response"

        elif scan_type == "STEALTH":
            pkt = IP(dst=ip, ttl=64) / TCP(sport=RandShort(), dport=port, flags="F")
            with SCAPY_LOCK:
                response = sr1(pkt, timeout=timeout_seconds, verbose=0)
            if response is None:
                status = "Filtered"
            elif response.haslayer(TCP) and response[TCP].flags == 0x14:
                status = "Closed"
            else:
                status = "Unknown TCP Response"
        elif scan_type == "CONNECT":
            try:
                with pysock.create_connection((ip, port), timeout=timeout_seconds):
                    status = "Open"
            except Exception as exc:
                msg = str(exc).lower()
                if "refused" in msg:
                    status = "Closed"
                elif "timeout" in msg:
                    status = "Filtered"
                else:
                    status = "Filtered"
        else:
            status = "Unsupported Scan Type"

        proto = "tcp" if scan_type in ("SYN", "STEALTH", "CONNECT") else "udp"
        service = get_port_service(port, proto=proto)
        version = ""
        details = {}
        if service_version and status.lower().startswith("open") and proto == "tcp":
            version = banner_grab(ip, port, timeout_seconds=max(0.3, timeout_seconds), host_header=host_header)
            details = enrich_open_port(ip, port, host_header, timeout_seconds=max(0.5, timeout_seconds))
        return {"port": port, "service": service, "status": status, "version": version, "details": details}
    except Exception as exc:
        return {"port": port, "service": "Error", "status": str(exc), "version": "", "details": {}}
