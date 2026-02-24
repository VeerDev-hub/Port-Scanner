def enrich(metadata, rows, args):
    hosts = {}
    for r in rows:
        host = r.get("host", "unknown")
        hosts.setdefault(host, {"open": 0, "closed": 0, "filtered": 0, "other": 0})
        status = str(r.get("status", "")).lower()
        if "open" in status:
            hosts[host]["open"] += 1
        elif "closed" in status:
            hosts[host]["closed"] += 1
        elif "filter" in status:
            hosts[host]["filtered"] += 1
        else:
            hosts[host]["other"] += 1
    return {"hosts": hosts, "host_count": len(hosts)}
