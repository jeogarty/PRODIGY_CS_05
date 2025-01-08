My fifth task as an intern at Prodigy InfoTech.

Task Title: Network Packet Analyzer

Task Description: Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source, and destination IP Addresses, protocols and payload data. Ensures the ethical use of the tool for educational purpose.

Prerequisites: 
1. Python 3.x: If you don't have Python installed yet, you can download it from python.org.
2. matplotlib: If you don't have matplotlib library installed yet, you can download it from matplotlib.org.

Features:
1.	Packet Capture: Captures network packets on a specified interface or all interfaces.
2.	Protocol Support: Displays details for TCP, UDP, ICMP, and other protocols.
3.	Payload Analysis: Extracts and displays the payload data (if available).
4.	Dynamic Interface Selection: Allows the user to specify a network interface or sniff on all interfaces.

Usage:
1.	Install the required library:
bash
pip install scapy
pip install matplotlib
3.	Run the script with elevated privileges (required for packet sniffing). For example:
bash
sudo python task5.py
4.	Specify the interface when prompted (e.g., eth0, wlan0, or leave blank for all interfaces).

Notes:
•	Elevated Privileges: Packet sniffing requires administrative/root access.
•	Payload Parsing: The script shows raw payload data. Additional parsing can be implemented for specific protocols (e.g., HTTP, DNS).
•	Ethical Use: This tool should only be used on networks you own or have permission to monitor.

