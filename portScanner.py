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

# Color codes for terminal output
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

def tcp_handshake(ipaddress, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        print(f"{CYAN}[+] Sending SYN to {ipaddress}:{port}{RESET}")
        sock.connect((ipaddress, port))
        print(f"{CYAN}[+] Received SYN-ACK from {ipaddress}:{port}{RESET}")
        print(f"{CYAN}[+] Sending ACK to {ipaddress}:{port}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error with {ipaddress}:{port} - {str(e)}{RESET}")
    finally:
        sock.close()

def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ipaddress, port))
        service = common_ports.get(port, "Unknown Service")
        print(f"{GREEN}[+] Port {port} ({service}) is Open{RESET}")
        tcp_handshake(ipaddress, port)
    except:
        # Do nothing if the port is closed
        pass
    finally:
        sock.close()

def start_scan(target, ports):
    print(f"\n{CYAN}Starting Scan for {target}{RESET}")
    print(f"{'-'*50}\n")
    threads = []
    for port in range(1, ports + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    print(f"\n{CYAN}Scan Complete for {target}.{RESET}\n{'='*50}\n")

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"{GREEN}[+] Resolved {domain} to IP: {ip_address}{RESET}")
        return ip_address
    except socket.gaierror:
        print(f"{RED}[-] Could not resolve domain: {domain}{RESET}")
        return None

if __name__ == "__main__":
    while True:
        target_input = input("Enter Target IP or Domain (or type 'quit' to exit): ").strip()
        
        if target_input.lower() == 'quit':
            print("Exiting the program.")
            break
        
        # Check if input is an IP or Domain
        if target_input.replace('.', '').isdigit():  # Simple check for an IP address
            target_ip = target_input
        else:
            target_ip = resolve_domain_to_ip(target_input)
        
        if target_ip:
            try:
                ports_to_scan = int(input("Enter number of ports to scan: ").strip())
                start_scan(target_ip, ports_to_scan)
            except ValueError:
                print(f"{RED}Please enter a valid number for ports.{RESET}")
