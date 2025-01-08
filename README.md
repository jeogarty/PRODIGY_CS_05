
Features:
1.	Packet Capture: Captures network packets on a specified interface or all interfaces.
2.	Protocol Support: Displays details for TCP, UDP, ICMP, and other protocols.
3.	Payload Analysis: Extracts and displays the payload data (if available).
4.	Dynamic Interface Selection: Allows the user to specify a network interface or sniff on all interfaces.
________________________________________
Usage:
1.	Install the required library:
bash
Copy code
pip install scapy
2.	Run the script with elevated privileges (required for packet sniffing). For example:
bash
Copy code
sudo python task5.py
3.	Specify the interface when prompted (e.g., eth0, wlan0, or leave blank for all interfaces).
________________________________________
Notes:
•	Elevated Privileges: Packet sniffing requires administrative/root access.
•	Payload Parsing: The script shows raw payload data. Additional parsing can be implemented for specific protocols (e.g., HTTP, DNS).
•	Ethical Use: This tool should only be used on networks you own or have permission to monitor.

