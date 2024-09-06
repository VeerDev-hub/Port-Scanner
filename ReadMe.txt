## Description

This project is a simple **Python-based port scanner** that scans common service ports and checks if they are open on a specified target IP address. It uses **multithreading** to speed up the scanning process, allowing for efficient scanning of multiple ports simultaneously.

## Features

- Scans specified number of ports on a single or multiple targets.
- Identifies common services running on open ports (e.g., HTTP, FTP, SSH).
- Multithreaded for fast scanning.
- Timeout handling to ensure efficient scanning even on non-responsive ports.

## Common Ports Scanned

The program includes a dictionary of the following common ports and their associated services:

- FTP (Data): 20
- FTP (Control): 21
- SSH: 22
- Telnet: 23
- SMTP: 25
- DNS: 53
- HTTP: 80
- POP3: 110
- IMAP: 143
- HTTPS: 443
- MySQL: 3306
- RDP: 3389
- HTTP-Proxy: 8080

## How to Use

### Prerequisites

You need to have Python 3.x installed on your machine. If you don't have Python installed, you can download it from the official website: [https://www.python.org/downloads/](https://www.python.org/downloads/).

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/VeerDev-hub/Port-Scanner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Port-Scanner
   ```

3. Run the script:
   ```bash
   python port_scanner.py
   ```

### Usage

1. When prompted, enter the target IP addresses (separated by commas if scanning multiple targets).
   
2. Specify the number of ports you wish to scan.

3. The program will start scanning the target(s) and display any open ports along with the service running on them.

#### Example:

```bash
[*] Enter Targets to scan (Separate by ','): 192.168.1.1
[*] Enter How many Ports you want to scan: 100
```

### Limitations

- Only scans up to the specified number of ports, starting from port 1.
- Common ports are predefined, but you can modify the `common_ports` dictionary to add more ports or customize services.

---
