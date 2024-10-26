import socket
import threading

# Dictionary for common ports and their services
common_ports = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP (Submission)", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy", 1433: "MSSQL",
    1521: "Oracle DB", 1723: "PPTP", 2049: "NFS", 2121: "FTP Admin",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Metasploit",
    5060: "SIP", 5432: "PostgreSQL", 5631: "PCAnywhere", 5900: "VNC",
    6000: "X11", 6379: "Redis", 6667: "IRC", 8000: "Common HTTP",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "SonarQube",
    9090: "Openfire", 9200: "Elasticsearch", 10000: "Webmin",
    27017: "MongoDB", 5040: "Citrix", 5357: "WSD", 8090: "Web App"
}

def tcp_handshake(ipaddress, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        print(f"[+] Sending SYN to {ipaddress}:{port}")
        sock.connect((ipaddress, port))
        print(f"[+] Received SYN-ACK from {ipaddress}:{port}")
        print(f"[+] Sending ACK to {ipaddress}:{port}")
    except Exception as e:
        print(f"[-] Error with {ipaddress}:{port} - {str(e)}")
    finally:
        sock.close()

def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ipaddress, port))
        service = common_ports.get(port, "Unknown Service")
        print(f"[+] Port {port} ({service}) is Open")
        tcp_handshake(ipaddress, port)
    except:
        pass
    finally:
        sock.close()

def start_scan(target, ports):
    print(f"\nStarting Scan for {target}")
    threads = []
    for port in range(1, ports + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    print("Scan Complete.\n")

if __name__ == "__main__":
    target_ip = input("Enter Target IP: ").strip()
    try:
        ports_to_scan = int(input("Enter number of ports to scan: ").strip())
        start_scan(target_ip, ports_to_scan)
    except ValueError:
        print("Please enter a valid number for ports.")
