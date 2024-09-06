import socket
import threading

# Dictionary for common ports and their services
common_ports = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

# Scan a specific port
def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.10)
        sock.connect((ipaddress, port))
        service = common_ports.get(port, "Unknown Service")
        print(f"[+] Port {port} ({service}) is Open")
    except:
        pass  
    finally:
        sock.close()

# Scan the target for the given number of ports
def scan(target, ports):
    print(f"\nStarting Scan for {target}")
    threads = []
    for port in range(1, ports + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

# Main program flow
targets = input("[*] Enter Targets to scan (Separate by ','): ")
ports = int(input("[*] Enter How many Ports you want to scan: "))
if ',' in targets:
    print("[*] Scanning Multiple Targets")
    for ip_addr in targets.split(','):
        scan(ip_addr.strip(), ports)
else:
    scan(targets.strip(), ports)