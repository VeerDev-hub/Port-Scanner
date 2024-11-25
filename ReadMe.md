Overview
This project is a simple Python-based port scanner that can scan a specified range of ports on a target IP address or domain. It performs a basic TCP handshake to determine if the port is open and attempts to retrieve the geolocation of the target IP address using the ipapi service.

Features:
Scans a range of ports and checks if they are open.
Performs a basic TCP handshake (SYN-ACK-ACK) on open ports.
Resolves a domain name to an IP address.
Fetches geolocation information based on the IP address.
Displays common port services like HTTP, HTTPS, FTP, MySQL, etc.
Requirements
Before running the script, you need to install the following Python package:

requests: This is used for making HTTP requests to the ipapi service to fetch geolocation data.
You can install the required dependencies by running the following command:

bash
Copy code
pip install -r requirements.txt
Installation
Clone the repository (if you're using Git):

bash
Copy code
git clone https://github.com/VeerDev-hub/port-scanner.git
cd port-scanner
Install dependencies:

Run the following command to install the required Python packages:

bash
Copy code
pip install -r requirements.txt
Usage
To use the port scanner:

Run the script:

In your terminal or command prompt, run the script:

bash
Copy code
python port_scanner.py
Provide input:

Enter a target IP address or domain name when prompted.
Optionally, specify the number of ports to scan (for example, 1-1024).
The script will display the open ports and their corresponding services.
It will also perform a TCP handshake and display the status.
Additionally, it will fetch and display the geolocation of the target IP.
Exit the script:

To exit the script, type quit when prompted for a target.

Example Output
less
Copy code
Enter Target IP or Domain (or type 'quit' to exit): example.com
[+] Resolved example.com to IP: 93.184.216.34
[+] Geolocation: Los Angeles, California, United States
[+] Initiating TCP Handshake on 93.184.216.34:80
[+] SYN-ACK Received from 93.184.216.34:80
[+] ACK Sent to 93.184.216.34:80
[+] Handshake Complete for 93.184.216.34:80
[+] Port 80 (HTTP) is Open
License
This project is open-source and available under the MIT License.

Contributing
Feel free to fork this project, submit issues, and create pull requests. Contributions are welcome!

Contact
If you have any questions or suggestions, please feel free to contact me via veerprataps.ranawat@gmail.com or create an issue in the GitHub repository.
