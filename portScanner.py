import socket
import threading
import requests

# Dictionary for common ports and their services
common_ports = {
    20: "FTP (Data Transfer)", 21: "FTP (Control)", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS Name Service", 138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD (Printer)", 520: "RIP", 
    587: "SMTP (Submission)", 631: "IPP (Internet Printing Protocol)", 
    636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS Proxy", 1194: "OpenVPN", 1433: "MSSQL", 
    1521: "Oracle DB", 1701: "L2TP", 1723: "PPTP", 
    2049: "NFS", 2121: "FTP Admin", 3306: "MySQL", 3389: "RDP",
    3690: "SVN", 4444: "Metasploit", 4567: "FRS", 
    5060: "SIP (Unencrypted)", 5061: "SIP (Encrypted)",
    5432: "PostgreSQL", 5631: "PCAnywhere", 5900: "VNC",
    5984: "CouchDB", 6000: "X11", 6379: "Redis", 
    6660: "IRC (Alternate)", 6667: "IRC", 8000: "Common HTTP",
    8080: "HTTP-Proxy", 8081: "HTTP Alternate", 
    8443: "HTTPS-Alt", 8888: "CDN or HTTP Proxy", 9000: "SonarQube",
    9090: "Openfire", 9200: "Elasticsearch REST API",
    9300: "Elasticsearch Node Communication", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB (Alternate)", 
    27019: "MongoDB (Sharding)", 28017: "MongoDB Web Interface",
    3000: "Grafana", 6379: "Redis", 1883: "MQTT", 5672: "AMQP",
    15672: "RabbitMQ Management", 27015: "Steam Game Server",
    25565: "Minecraft Server", 8086: "InfluxDB", 9092: "Kafka",
    10250: "Kubernetes API", 2379: "etcd", 6443: "Kubernetes API Secure",
    5000: "UPnP", 50000: "SAP Router", 49152: "Dynamic/Private Ports",
    3128: "Squid Proxy", 4321: "Timbuktu Remote Desktop", 4443: "HTTPS/Oracle (Encrypted)", 
    8090: "Jetty HTTP Server/Webmin", 8443: "HTTPS-Alt/Glassfish", 9922: "SSHD or Web Management",
    2053: "Cloudflare proxy (likely)",
    2052: "Cloudflare proxy (likely)",
    2082: "cPanel (Web Hosting Control Panel) - HTTP",
    2083: "cPanel (Web Hosting Control Panel) - HTTPS",
    2087: "cPanel (Web Hosting Control Panel) - WHM",
    2086: "cPanel (Web Hosting Control Panel) - Alternative HTTP",
    2095: "Webmail (cPanel)",
    2096: "Webmail (cPanel)",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt/Glassfish",
    8880: "Proxy or Web Application Service (likely)",
}




# Color codes for terminal output
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
RESET = "\033[0m"

def get_geolocation(ip_address):
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country_name', 'Unknown')}"
            print(f"{GREEN}[+] Geolocation: {location}{RESET}")
        else:
            print(f"{RED}[-] Failed to retrieve geolocation data for {ip_address}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error fetching geolocation: {str(e)}{RESET}")

def tcp_handshake(ipaddress, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        print(f"{CYAN}[+] Initiating TCP Handshake on {ipaddress}:{port}{RESET}")
        
        # Send SYN
        sock.connect((ipaddress, port))
        print(f"{CYAN}[+] SYN-ACK Received from {ipaddress}:{port}{RESET}")
        
        # Simulate ACK
        print(f"{CYAN}[+] ACK Sent to {ipaddress}:{port}{RESET}")
        print(f"{GREEN}[+] Handshake Complete for {ipaddress}:{port}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Handshake Failed for {ipaddress}:{port} - {str(e)}{RESET}")
    finally:
        sock.close()

def scan_port(ipaddress, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((ipaddress, port))
        service = common_ports.get(port, "Unknown Service")
        print(f"{GREEN}[+] Port {port} ({service}) is Open{RESET}")
        
        # Perform TCP handshake
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
            # Fetch geolocation before scanning
            get_geolocation(target_ip)
            try:
                ports_to_scan = int(input("Enter number of ports to scan: ").strip())
                start_scan(target_ip, ports_to_scan)
            except ValueError:
                print(f"{RED}Please enter a valid number for ports.{RESET}")
