import re


def extract_domain(target):
    target = (target or "").strip().lower()
    if not target:
        return ""

    # URL mode: keep host only.
    if target.startswith("http://") or target.startswith("https://"):
        target = re.sub(r"https?://", "", target)
        return target.split("/", 1)[0]

    # Preserve CIDR notation like 192.168.1.0/24.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", target):
        return target

    return target.split("/", 1)[0]


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() == "true"


def parse_port_targets(port_range_raw=None, ports_count_raw=None):
    """
    Supports:
    - range/list expression: "1-1024,3306,8080"
    - fallback count mode: first N ports (1..N)
    """
    port_range_text = (str(port_range_raw or "")).strip()
    if port_range_text:
        ports = set()
        chunks = [c.strip() for c in port_range_text.split(",") if c.strip()]
        if not chunks:
            raise ValueError("Empty port range")

        for chunk in chunks:
            if "-" in chunk:
                parts = [p.strip() for p in chunk.split("-", 1)]
                if len(parts) != 2 or not parts[0] or not parts[1]:
                    raise ValueError(f"Invalid range segment: {chunk}")
                start = int(parts[0])
                end = int(parts[1])
                if start > end:
                    raise ValueError(f"Range start must be <= end: {chunk}")
                if start < 1 or end > 65535:
                    raise ValueError(f"Port out of bounds in range: {chunk}")
                ports.update(range(start, end + 1))
            else:
                port = int(chunk)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of bounds: {chunk}")
                ports.add(port)

        ordered = sorted(ports)
        if not ordered:
            raise ValueError("No valid ports parsed")
        return ordered, port_range_text

    try:
        ports_to_scan = int(ports_count_raw if ports_count_raw is not None else 100)
    except Exception as exc:
        raise ValueError("Invalid ports value") from exc
    ports_to_scan = max(1, min(65535, ports_to_scan))
    return list(range(1, ports_to_scan + 1)), f"1-{ports_to_scan}"
